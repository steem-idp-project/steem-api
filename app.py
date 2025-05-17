import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import requests
from flask import Flask, g, jsonify, request

# --- Environment Variables ---
AUTH_API_HOST = os.getenv("AUTH_API_HOST")
if not AUTH_API_HOST:
    raise ValueError("AUTH_API_HOST environment variable is not set")
AUTH_API_PORT = os.getenv("AUTH_API_PORT")
if not AUTH_API_PORT:
    raise ValueError("AUTH_API_PORT environment variable is not set")

IO_API_HOST = os.getenv("IO_API_HOST")
if not IO_API_HOST:
    raise ValueError("IO_API_HOST environment variable is not set")

IO_API_PORT = os.getenv("IO_API_PORT")
if not IO_API_PORT:
    raise ValueError("IO_API_PORT environment variable is not set")

IO_API_URL = f"http://{IO_API_HOST}:{IO_API_PORT}"
AUTH_API_URL = f"http://{AUTH_API_HOST}:{AUTH_API_PORT}"

app = Flask(__name__)
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY", "a_secure_random_secret_key_for_steem_api"
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
app.logger.setLevel(logging.INFO)


GAME_STATUS_PENDING = "pending"
GAME_STATUS_APPROVED = "approved"
GAME_STATUS_REJECTED = "rejected"

RETURN_WINDOW_HOURS = 48
MAX_PLAYTIME_FOR_RETURN_HOURS = 2


# --- Helper Functions & Decorators ---
def _validate_auth_token(token):
    """Helper to call Auth API for token validation."""
    try:
        response = requests.post(
            f"{AUTH_API_URL}/validate", json={"auth_token": token}, timeout=5
        )
        if response.status_code == 200:
            return response.json()
        app.logger.warning(
            "Auth API validation failed for token: Status %s - %s",
            response.status_code,
            response.text,
        )
        return None
    except requests.exceptions.Timeout:
        app.logger.error("Timeout calling Auth API /validate")
        return None
    except requests.exceptions.RequestException as e:
        app.logger.error("Error calling Auth API /validate: %s", e)
        return None


def require_auth(admin_required=False, publisher_required=False):
    """Decorator to enforce authentication and role-based access."""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_token = request.cookies.get("auth_token")
            if not auth_token:
                return jsonify({"error": "Authentication token required"}), 401

            claims = _validate_auth_token(auth_token)
            if not claims:
                return jsonify({"error": "Invalid or expired token"}), 401

            g.user_claims = claims

            if admin_required and not claims.get("is_admin"):
                return jsonify({"error": "Admin privileges required"}), 403
            if publisher_required and not claims.get("is_publisher"):
                return jsonify({"error": "Publisher privileges required"}), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def _make_io_api_request(method, endpoint, **kwargs):
    """Wrapper for requests to IO API with error handling and logging."""
    try:
        url = f"{IO_API_URL}{endpoint}"
        app.logger.debug(
            "Making IO API request: %s %s with params %s and json %s",
            method.upper(),
            url,
            kwargs.get("params"),
            kwargs.get("json"),
        )
        response = requests.request(method, url, timeout=10, **kwargs)
        response.raise_for_status()

        if response.content:
            if response.headers.get("Content-Type") == "application/json":
                return response.json()
            app.logger.warning(
                "IO API response for %s %s is not JSON: %s",
                method.upper(),
                url,
                response.text[:100],
            )
            return response.text
        return None
    except requests.exceptions.Timeout:
        app.logger.error("Timeout calling IO API: %s %s", method.upper(), endpoint)
        raise
    except requests.exceptions.HTTPError as e:
        err_msg = f"IO API HTTPError: {method.upper()} {endpoint} - Status {e.response.status_code}"
        try:
            err_detail = e.response.json()
            app.logger.error("%s - Detail: %s", err_msg, err_detail)
        except ValueError:
            app.logger.error("%s - Response: %s", err_msg, e.response.text[:200])
        raise
    except requests.exceptions.RequestException as e:
        app.logger.error(
            "IO API RequestException: %s %s - %s", method.upper(), endpoint, e
        )
        raise


# --- Health Check ---
@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint to verify the status of the API and its dependencies.
    """
    auth_ok, io_ok = False, False
    try:
        if requests.get(f"{AUTH_API_URL}/health", timeout=2).status_code == 200:
            auth_ok = True
    except requests.exceptions.RequestException:
        app.logger.warning("Health check: Auth API unreachable or unhealthy")
    try:
        if requests.get(f"{IO_API_URL}/health", timeout=2).status_code == 200:
            io_ok = True
    except requests.exceptions.RequestException:
        app.logger.warning("Health check: IO API unreachable or unhealthy")

    if auth_ok and io_ok:
        return (
            jsonify(
                {
                    "status": "healthy",
                    "dependencies": {"auth_api": "ok", "io_api": "ok"},
                }
            ),
            200,
        )

    return (
        jsonify(
            {
                "status": "unhealthy",
                "dependencies": {
                    "auth_api": "ok" if auth_ok else "error",
                    "io_api": "ok" if io_ok else "error",
                },
            }
        ),
        503,
    )


# --- Non-Authenticated User Endpoints ---
@app.route("/games", methods=["GET"])
def list_games():
    """
    List all games available for purchase.
    """
    try:
        all_games = _make_io_api_request("get", "/games")
        approved_games = [
            game for game in all_games if game.get("status") == GAME_STATUS_APPROVED
        ]
        return jsonify(approved_games), 200
    except requests.exceptions.RequestException:
        return jsonify({"error": "Failed to retrieve games from service"}), 500


@app.route("/games/<int:gid>", methods=["GET"])
def get_game_detail(gid):
    """
    Get details of a specific game by its ID.
    """
    try:
        game = _make_io_api_request("get", f"/games/{gid}")
        if game.get("status") != GAME_STATUS_APPROVED:
            return jsonify({"error": "Game not accessible"}), 403
        return jsonify(game), 200
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return jsonify({"error": "Game not found"}), 404
        return (
            jsonify({"error": "Failed to retrieve game details"}),
            e.response.status_code,
        )
    except requests.exceptions.RequestException:
        return jsonify({"error": f"Failed to retrieve game {gid} from service"}), 500


# --- Authenticated User Endpoints ---
@app.route("/wallet/deposit", methods=["POST"])
@require_auth()
def deposit_wallet():
    """
    Deposit an amount into the user's wallet.
    """
    data = request.get_json()
    if not data or "amount" not in data:
        return jsonify({"error": "Amount is required"}), 400
    try:
        amount = int(data["amount"])
        if amount <= 0:
            return jsonify({"error": "Deposit amount must be a positive integer"}), 400
    except ValueError:
        return jsonify({"error": "Invalid amount format, must be an integer"}), 400

    user_uid = g.user_claims["uid"]
    try:
        wallet_data = _make_io_api_request("get", f"/wallets/{user_uid}")
        current_balance = int(wallet_data.get("balance", 0))
        new_balance = current_balance + amount
        updated_wallet = _make_io_api_request(
            "put", f"/wallets/{user_uid}", json={"balance": new_balance}
        )
        return jsonify(updated_wallet), 200
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            app.logger.error(
                "Wallet not found for user %s during deposit. Data integrity issue.",
                user_uid,
            )
            return (
                jsonify({"error": "User wallet not found. Please contact support."}),
                500,
            )
        return (
            jsonify({"error": "Failed to update wallet balance via IO API"}),
            e.response.status_code,
        )
    except requests.exceptions.RequestException:
        return (
            jsonify(
                {
                    "error": "Failed to update wallet balance due to service connection issue"
                }
            ),
            500,
        )
    except (TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error in deposit_wallet for user %s: %s",
            user_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/wallet", methods=["GET"])
@require_auth()
def get_wallet_balance():
    """
    Get the current balance of the user's wallet.
    """
    user_uid = g.user_claims["uid"]
    try:
        wallet_data = _make_io_api_request("get", f"/wallets/{user_uid}")
        return jsonify(wallet_data), 200
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            app.logger.warning(
                "Wallet not found for user %s when fetching balance.", user_uid
            )
            return jsonify({"error": "Wallet not found"}), 404
        return (
            jsonify({"error": "Failed to retrieve wallet balance via IO API"}),
            e.response.status_code,
        )
    except requests.exceptions.RequestException:
        return (
            jsonify(
                {
                    "error": "Failed to retrieve wallet balance due to service connection issue"
                }
            ),
            500,
        )
    except (TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error in get_wallet_balance for user %s: %s",
            user_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/users/me/library", methods=["GET"])
@require_auth()
def get_my_library():
    """
    Get the user's game library, including purchase history and playtime.
    """
    user_uid = g.user_claims["uid"]
    try:
        purchases = _make_io_api_request(
            "get", "/purchases", params={"user_id": user_uid}
        )
        library_games = [
            {
                "purchase_id": p["pid"],
                "game_id": p["game_id"],
                "game_name": p.get("game_name", "N/A"),
                "purchase_date": p["date"],
                "hours_played": p["hours_played"],
            }
            for p in purchases
        ]
        return jsonify(library_games), 200
    except requests.exceptions.RequestException:
        return (
            jsonify({"error": "Failed to retrieve game library due to service issue"}),
            500,
        )
    except (TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error in get_my_library for user %s: %s",
            user_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/games/<int:gid>/purchase", methods=["POST"])
@require_auth()
def purchase_game(gid):
    """
    Purchase a game by its ID.
    """
    user_uid = g.user_claims["uid"]
    try:
        game_data = _make_io_api_request("get", f"/games/{gid}")
        if game_data.get("status") != GAME_STATUS_APPROVED:
            return jsonify({"error": "Game is not available for purchase"}), 403

        game_price = int(game_data.get("price"))

        existing_purchases = _make_io_api_request(
            "get", "/purchases", params={"user_id": user_uid, "game_id": gid}
        )
        if existing_purchases:
            return jsonify({"error": "Game already purchased"}), 409

        wallet_data = _make_io_api_request("get", f"/wallets/{user_uid}")
        user_balance = int(wallet_data.get("balance"))

        if user_balance < game_price:
            return jsonify({"error": "Insufficient funds"}), 402

        created_purchase = _make_io_api_request(
            "post", "/purchases", json={"user_id": user_uid, "game_id": gid}
        )

        new_user_balance = user_balance - game_price
        _make_io_api_request(
            "put", f"/wallets/{user_uid}", json={"balance": new_user_balance}
        )

        publisher_uid = game_data.get("publisher")
        if publisher_uid is None:
            app.logger.error(
                "Game %s is missing publisher information. "
                "Cannot process payment to publisher for purchase by user %s.",
                gid,
                user_uid,
            )
        else:
            try:
                publisher_wallet_data = _make_io_api_request(
                    "get", f"/wallets/{publisher_uid}"
                )
                publisher_current_balance = int(publisher_wallet_data.get("balance", 0))

                publisher_earnings = game_price
                publisher_new_balance = publisher_current_balance + publisher_earnings

                _make_io_api_request(
                    "put",
                    f"/wallets/{publisher_uid}",
                    json={"balance": publisher_new_balance},
                )
                app.logger.info(
                    "Successfully credited %s to publisher %s for game %s purchase by user %s.",
                    publisher_earnings,
                    publisher_uid,
                    gid,
                    user_uid,
                )
            except requests.exceptions.HTTPError as pub_http_err:
                app.logger.error(
                    "Failed to update publisher %s's wallet for game %s purchase by user %s. HTTPError: %s",
                    publisher_uid,
                    gid,
                    user_uid,
                    "%s"
                    % (
                        pub_http_err.response.text
                        if getattr(pub_http_err, "response", None)
                        else str(pub_http_err)
                    ),
                )
            except (
                requests.exceptions.RequestException,
                ValueError,
                TypeError,
                KeyError,
            ) as pub_err:
                app.logger.error(
                    "Failed to update publisher %s's wallet for game %s purchase "
                    "by user %s due to service or data error: %s",
                    publisher_uid,
                    gid,
                    user_uid,
                    pub_err,
                    exc_info=True,
                )

        return (
            jsonify(
                {
                    "message": "Game purchased successfully",
                    "purchase_details": created_purchase,
                }
            ),
            201,
        )
    except requests.exceptions.HTTPError as e:
        if (
            e.response is not None
            and e.response.status_code == 404
            and e.request
            and f"/games/{gid}" in e.request.url
        ):
            return jsonify({"error": "Game not found"}), 404
        app.logger.error(
            "IO API HTTPError during purchase of game %s for user %s: %s",
            gid,
            user_uid,
            e.response.text if getattr(e, "response", None) else str(e),
        )
        return jsonify(
            {"error": "Failed to purchase game due to backend data issue"}
        ), (e.response.status_code if getattr(e, "response", None) else 500)
    except requests.exceptions.RequestException as req_e:
        app.logger.error(
            "RequestException during purchase of game %s for user %s: %s",
            gid,
            user_uid,
            req_e,
            exc_info=True,
        )
        return (
            jsonify(
                {"error": "Failed to purchase game due to service connection issue"}
            ),
            500,
        )
    except (
        TypeError,
        KeyError,
        ValueError,
    ) as data_err:
        app.logger.error(
            "Data error during purchase_game %s for user %s: %s",
            gid,
            user_uid,
            data_err,
            exc_info=True,
        )
        return (
            jsonify(
                {"error": "An unexpected server error occurred due to data issues"}
            ),
            500,
        )


@app.route("/games/<int:gid>/wishlist", methods=["POST"])
@require_auth()
def add_to_wishlist(gid):
    """
    Add a game to the user's wishlist.
    """
    app.logger.info(
        "Wishlist POST for game %s by user %s - Not Implemented",
        gid,
        g.user_claims["uid"],
    )
    return jsonify({"message": "Wishlist functionality not implemented"}), 501


@app.route("/games/<int:gid>/wishlist", methods=["DELETE"])
@require_auth()
def remove_from_wishlist(gid):
    """
    Remove a game from the user's wishlist.
    """
    app.logger.info(
        "Wishlist DELETE for game %s by user %s - Not Implemented",
        gid,
        g.user_claims["uid"],
    )
    return jsonify({"message": "Wishlist functionality not implemented"}), 501


@app.route("/purchases/<int:pid>/return", methods=["POST"])
@require_auth()
def return_game(pid):
    """
    Return a purchased game within the allowed return window.
    This will also debit the publisher's wallet for the returned game's price.
    """
    user_uid = g.user_claims["uid"]
    game_id_for_logging = "unknown"

    try:
        purchase_data = _make_io_api_request("get", f"/purchases/{pid}")
        game_id_for_logging = purchase_data.get("game_id", "unknown")

        if purchase_data.get("user_id") != user_uid:
            return jsonify({"error": "This purchase does not belong to you"}), 403

        purchase_date_str = purchase_data.get("date")
        try:
            purchase_datetime_obj = datetime.strptime(
                purchase_date_str, "%a, %d %b %Y %H:%M:%S GMT"
            )
            purchase_datetime_utc = purchase_datetime_obj.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError) as ve:
            app.logger.error(
                "Could not parse purchase date string '%s' for purchase PID %s: %s. Investigate IO API date format.",
                purchase_date_str,
                pid,
                ve,
                exc_info=True,
            )
            return (
                jsonify(
                    {
                        "error": "Invalid purchase date format in record, cannot process return."
                    }
                ),
                500,
            )

        if datetime.now(timezone.utc) > purchase_datetime_utc + timedelta(
            hours=RETURN_WINDOW_HOURS
        ):
            return (
                jsonify(
                    {
                        "error": f"Return period of {RETURN_WINDOW_HOURS} hours has expired for purchase PID {pid}"
                    }
                ),
                403,
            )

        hours_played = int(purchase_data.get("hours_played", 0))
        if hours_played > MAX_PLAYTIME_FOR_RETURN_HOURS:
            return (
                jsonify(
                    {
                        "error": (
                            f"Game (PID: {pid}) played for {hours_played} hours, "
                            f"exceeding the allowed {MAX_PLAYTIME_FOR_RETURN_HOURS} hours for return."
                        )
                    }
                ),
                403,
            )

        game_id = purchase_data.get("game_id")
        if game_id is None:
            app.logger.error(
                "Purchase PID %s is missing game_id. Cannot process return.", pid
            )
            return (
                jsonify({"error": "Corrupted purchase record: missing game ID."}),
                500,
            )

        game_data = _make_io_api_request("get", f"/games/{game_id}")
        game_price = int(game_data.get("price"))
        publisher_uid = game_data.get("publisher")

        _make_io_api_request("delete", f"/purchases/{pid}")

        user_wallet_data = _make_io_api_request("get", f"/wallets/{user_uid}")
        user_current_balance = int(user_wallet_data.get("balance"))
        user_new_balance = user_current_balance + game_price
        _make_io_api_request(
            "put", f"/wallets/{user_uid}", json={"balance": user_new_balance}
        )
        app.logger.info(
            "User %s successfully refunded %d for purchase PID %s.",
            user_uid,
            game_price,
            pid,
        )

        if publisher_uid is None:
            app.logger.error(
                "Game %s (from purchase PID %s) is missing publisher information. "
                "Cannot debit publisher for user %s's return.",
                game_id,
                pid,
                user_uid,
            )
        else:
            try:
                publisher_wallet_data = _make_io_api_request(
                    "get", f"/wallets/{publisher_uid}"
                )
                publisher_current_balance = int(publisher_wallet_data.get("balance", 0))

                publisher_new_balance = publisher_current_balance - game_price

                _make_io_api_request(
                    "put",
                    f"/wallets/{publisher_uid}",
                    json={"balance": publisher_new_balance},
                )
                app.logger.info(
                    "Successfully debited %d from publisher %s for game %s (purchase PID %s) returned by user %s.",
                    game_price,
                    publisher_uid,
                    game_id,
                    pid,
                    user_uid,
                )
            except requests.exceptions.HTTPError as pub_http_err:
                app.logger.error(
                    "Failed to update publisher %s's wallet for game %s (purchase PID %s) returned by user %s. HTTPError: %s",
                    publisher_uid,
                    game_id,
                    pid,
                    user_uid,
                    (
                        pub_http_err.response.text
                        if getattr(pub_http_err, "response", None)
                        else str(pub_http_err)
                    ),
                )
            except (
                requests.exceptions.RequestException,
                ValueError,
                TypeError,
                KeyError,
            ) as pub_err:
                app.logger.error(
                    "Failed to update publisher %s's wallet for game %s (purchase PID %s) returned by user %s due to service or data error: %s",
                    publisher_uid,
                    game_id,
                    pid,
                    user_uid,
                    pub_err,
                    exc_info=True,
                )
        return (
            jsonify({"message": "Game returned successfully. Refund processed."}),
            200,
        )
    except requests.exceptions.HTTPError as e:
        err_resp = getattr(e, "response", None)
        if err_resp is not None and err_resp.status_code == 404:
            if e.request and f"/purchases/{pid}" in e.request.url:
                return jsonify({"error": f"Purchase record PID {pid} not found"}), 404
            if e.request and f"/games/{game_id_for_logging}" in e.request.url:
                app.logger.error(
                    "Game GID:%s for purchase PID:%s not found during return processing.",
                    game_id_for_logging,
                    pid,
                )
                return (
                    jsonify(
                        {
                            "error": "Associated game data not found, cannot process refund."
                        }
                    ),
                    500,
                )
        app.logger.error(
            "IO API HTTPError during return of purchase PID %s (Game GID: %s): %s",
            pid,
            game_id_for_logging,
            err_resp.text if err_resp else str(e),
        )
        return jsonify({"error": "Failed to return game due to backend data issue"}), (
            err_resp.status_code if err_resp else 500
        )
    except requests.exceptions.RequestException as req_e:
        app.logger.error(
            "RequestException during return of purchase PID %s (Game GID: %s) for user %s: %s",
            pid,
            game_id_for_logging,
            user_uid,
            req_e,
            exc_info=True,
        )
        return (
            jsonify({"error": "Failed to return game due to service connection issue"}),
            500,
        )
    except (TypeError, KeyError, ValueError) as data_err:
        app.logger.error(
            "Data error during return_game PID %s (Game GID: %s) for user %s: %s",
            pid,
            game_id_for_logging,
            user_uid,
            data_err,
            exc_info=True,
        )
        return (
            jsonify(
                {"error": "An unexpected server error occurred due to data issues"}
            ),
            500,
        )


@app.route("/games/<int:gid>/play", methods=["POST"])
@require_auth()
def play_game_action(gid):
    """
    Check if the user has purchased the game and allow them to play it.
    """
    user_uid = g.user_claims["uid"]
    try:
        purchases = _make_io_api_request(
            "get", "/purchases", params={"user_id": user_uid, "game_id": gid}
        )
        if not purchases:
            return (
                jsonify({"error": "You do not own this game or game ID is invalid"}),
                403,
            )
        return jsonify({"message": "Access to game confirmed. Happy gaming!"}), 200
    except requests.exceptions.RequestException:
        return (
            jsonify({"error": "Failed to verify game ownership due to service issue"}),
            500,
        )
    except (TypeError, KeyError, ValueError) as e:
        app.logger.error(
            "Unexpected error in play_game_action for game %s, user %s: %s",
            gid,
            user_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


# --- Publisher/Developer Endpoints ---
@app.route("/users/me/games", methods=["GET"])
@require_auth(publisher_required=True)
def get_my_published_games():
    """
    Get the list of games published by the authenticated publisher.
    """
    publisher_uid = g.user_claims["uid"]
    try:
        all_games = _make_io_api_request("get", "/games")
        publisher_games = [
            game for game in all_games if game.get("publisher") == publisher_uid
        ]
        return jsonify(publisher_games), 200
    except requests.exceptions.RequestException:
        return (
            jsonify(
                {"error": "Failed to retrieve published games due to service issue"}
            ),
            500,
        )
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error in get_my_published_games for publisher %s: %s",
            publisher_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/games", methods=["POST"])
@require_auth(publisher_required=True)
def publish_new_game():
    """
    Publish a new game by the authenticated publisher.
    """
    publisher_uid = g.user_claims["uid"]
    data = request.get_json()
    if not data or not data.get("name") or data.get("price") is None:
        return jsonify({"error": "Name and price (integer) are required fields"}), 400

    try:
        price = int(data["price"])
        if price < 0:
            return jsonify({"error": "Price cannot be negative"}), 400
    except ValueError:
        return jsonify({"error": "Invalid price format, must be an integer"}), 400

    game_payload = {
        "name": data["name"],
        "description": data.get("description", ""),
        "price": price,
        "publisher": publisher_uid,
        "status": GAME_STATUS_PENDING,
    }
    try:
        created_game = _make_io_api_request("post", "/games", json=game_payload)
        return jsonify(created_game), 201
    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code == 500:
            try:
                io_error_detail = e.response.json().get("detail", "")
                if (
                    "unique constraint" in io_error_detail.lower()
                    or "duplicate key" in io_error_detail.lower()
                ):
                    return (
                        jsonify({"error": "A game with this name may already exist."}),
                        409,
                    )
            except ValueError:
                pass
        app.logger.error(
            "IO API HTTPError creating game for publisher %s: %s",
            publisher_uid,
            e.response.text if e.response else str(e),
        )
        return jsonify(
            {"error": "Failed to publish new game due to backend data issue"}
        ), (e.response.status_code if e.response else 500)
    except requests.exceptions.RequestException:
        return (
            jsonify(
                {"error": "Failed to publish new game due to service connection issue"}
            ),
            500,
        )
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error in publish_new_game for publisher %s: %s",
            publisher_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/games/<int:gid>", methods=["PUT"])
@require_auth(publisher_required=True)
def update_published_game(gid):
    """
    Update the details of a game published by the authenticated publisher.
    """
    publisher_uid = g.user_claims["uid"]
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body cannot be empty for update"}), 400

    try:
        game_data = _make_io_api_request("get", f"/games/{gid}")
        if game_data.get("publisher") != publisher_uid:
            return (
                jsonify({"error": "You do not have permission to update this game"}),
                403,
            )

        update_payload = {}
        if "name" in data:
            update_payload["name"] = data["name"]
        if "description" in data:
            update_payload["description"] = data["description"]
        if "price" in data:
            try:
                price = int(data["price"])
                if price < 0:
                    return jsonify({"error": "Price cannot be negative"}), 400
                update_payload["price"] = price
            except ValueError:
                return (
                    jsonify({"error": "Invalid price format, must be an integer"}),
                    400,
                )

        if not update_payload:
            return jsonify({"error": "No valid or updatable fields provided"}), 400

        current_status = game_data.get("status")
        if current_status in {GAME_STATUS_APPROVED, GAME_STATUS_REJECTED}:
            update_payload["status"] = GAME_STATUS_PENDING
        elif current_status == GAME_STATUS_PENDING:
            update_payload["status"] = GAME_STATUS_PENDING

        updated_game = _make_io_api_request("put", f"/games/{gid}", json=update_payload)
        return jsonify(updated_game), 200
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return jsonify({"error": "Game not found"}), 404
        app.logger.error(
            "IO API HTTPError updating game %s for publisher %s: %s",
            gid,
            publisher_uid,
            e.response.text if e.response else str(e),
        )
        return jsonify({"error": "Failed to update game due to backend data issue"}), (
            e.response.status_code if e.response else 500
        )
    except requests.exceptions.RequestException:
        return (
            jsonify({"error": "Failed to update game due to service connection issue"}),
            500,
        )
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error in update_published_game %s for publisher %s: %s",
            gid,
            publisher_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/games/<int:gid>", methods=["DELETE"])
@require_auth(publisher_required=True)
def delete_published_game(gid):
    """
    Delete a game published by the authenticated publisher.
    """
    publisher_uid = g.user_claims["uid"]
    try:
        game_data = _make_io_api_request("get", f"/games/{gid}")
        if game_data.get("publisher") != publisher_uid:
            return (
                jsonify({"error": "You do not have permission to delete this game"}),
                403,
            )

        _make_io_api_request("delete", f"/games/{gid}")
        return jsonify({"message": f"Game {gid} deleted successfully"}), 200
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return jsonify({"error": "Game not found or already deleted"}), 404
        app.logger.error(
            "IO API HTTPError deleting game %s for publisher %s: %s",
            gid,
            publisher_uid,
            e.response.text if e.response else str(e),
        )
        return jsonify({"error": "Failed to delete game due to backend data issue"}), (
            e.response.status_code if e.response else 500
        )
    except requests.exceptions.RequestException:
        return (
            jsonify({"error": "Failed to delete game due to service connection issue"}),
            500,
        )
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error in delete_published_game %s for publisher %s: %s",
            gid,
            publisher_uid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/users/me/profits", methods=["GET"])
@require_auth(publisher_required=True)
def get_my_profits():
    """
    Calculate the estimated profits for the authenticated publisher.
    """
    publisher_uid = g.user_claims["uid"]
    total_profit = 0
    try:
        all_io_games = _make_io_api_request("get", "/games")
        publisher_games_approved = [
            game
            for game in all_io_games
            if game.get("publisher") == publisher_uid
            and game.get("status") == GAME_STATUS_APPROVED
        ]

        for game in publisher_games_approved:
            game_id = game["gid"]
            game_price = int(game["price"])
            purchases_for_game = _make_io_api_request(
                "get", "/purchases", params={"game_id": game_id}
            )
            total_profit += len(purchases_for_game) * game_price

        return (
            jsonify(
                {
                    "publisher_uid": publisher_uid,
                    "total_estimated_profits": total_profit,
                }
            ),
            200,
        )
    except requests.exceptions.RequestException:
        return (
            jsonify({"error": "Failed to calculate profits due to service issue"}),
            500,
        )
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Unexpected error calculating profits for publisher %s: %s",
            publisher_uid,
            e,
            exc_info=True,
        )
        return (
            jsonify(
                {"error": "An unexpected error occurred while calculating profits"}
            ),
            500,
        )


# --- Admin Endpoints ---
@app.route("/admin/games", methods=["GET"])
@require_auth(admin_required=True)
def admin_list_all_games():
    """
    List all games in the system, regardless of their status.
    """
    try:
        games = _make_io_api_request("get", "/games")
        return jsonify(games), 200
    except requests.exceptions.RequestException:
        return jsonify({"error": "Failed to retrieve all games from service"}), 500
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Admin: Unexpected error in admin_list_all_games: %s", e, exc_info=True
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/admin/games/<int:gid>", methods=["GET"])
@require_auth(admin_required=True)
def admin_get_game_detail(gid):
    """
    Get detailed information about a specific game by its ID.
    """
    try:
        game = _make_io_api_request("get", f"/games/{gid}")
        return jsonify(game), 200
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return jsonify({"error": "Game not found"}), 404
        return (
            jsonify({"error": f"Failed to retrieve game {gid} via IO API"}),
            e.response.status_code,
        )
    except requests.exceptions.RequestException:
        return jsonify({"error": f"Failed to retrieve game {gid} from service"}), 500
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Admin: Unexpected error in admin_get_game_detail for %s: %s",
            gid,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


def _admin_change_game_status(gid, new_status):
    """
    Change the status of a game to either approved or rejected.
    """
    try:
        _make_io_api_request("get", f"/games/{gid}")
        updated_game = _make_io_api_request(
            "put", f"/games/{gid}", json={"status": new_status}
        )
        return jsonify(updated_game), 200
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return jsonify({"error": "Game not found, cannot change status"}), 404
        app.logger.error(
            "Admin: IO API HTTPError changing status of game %s to %s: %s",
            gid,
            new_status,
            e.response.text if e.response else str(e),
        )
        return jsonify({"error": "Failed to change game status via IO API"}), (
            e.response.status_code if e.response else 500
        )
    except requests.exceptions.RequestException:
        return (
            jsonify(
                {
                    "error": "Failed to change game status due to service connection issue"
                }
            ),
            500,
        )
    except (ValueError, TypeError, KeyError) as e:
        app.logger.error(
            "Admin: Unexpected error changing status for game %s to %s: %s",
            gid,
            new_status,
            e,
            exc_info=True,
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500


@app.route("/admin/games/<int:gid>/approve", methods=["POST"])
@require_auth(admin_required=True)
def admin_approve_game(gid):
    """
    Approve a game for publication.
    """
    return _admin_change_game_status(gid, GAME_STATUS_APPROVED)


@app.route("/admin/games/<int:gid>/reject", methods=["POST"])
@require_auth(admin_required=True)
def admin_reject_game(gid):
    """
    Reject a game from publication.
    """
    return _admin_change_game_status(gid, GAME_STATUS_REJECTED)


@app.route("/admin/users", methods=["GET"])
@require_auth(admin_required=True)
def admin_list_users():
    """
    List all users in the system.
    """
    try:
        users = _make_io_api_request("get", "/users")
        return jsonify(users), 200
    except requests.exceptions.RequestException:
        return jsonify({"error": "Failed to retrieve all users from service"}), 500
    except (ValueError, TypeError) as e:
        app.logger.error(
            "Admin: Unexpected error in admin_list_users: %s", e, exc_info=True
        )
        return jsonify({"error": "An unexpected server error occurred"}), 500
