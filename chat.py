# chat.py
import datetime
from flask import current_app
from flask_socketio import Namespace, emit, join_room

class ChatNamespace(Namespace):
    def _db(self):
        return current_app.db

    def _serialise(self, doc):
        return {
            "room":       doc["room"],
            "from":       doc["from"],
            "to":         doc["to"],
            "ciphertext": doc["ciphertext"],
            "iv":         doc["iv"],
            "ephemeralPubKey": doc["ephemeralPubKey"],
            "timestamp":  doc["timestamp"].isoformat()
        }

    def on_join(self, data):
        room = data["room"]
        user = data["user"]
        join_room(room)

        # Fetch messages where user is sender OR recipient
        msgs = (
            self._db().messages
                .find({
                    "room": room,
                    "$or": [
                        {"from": user},
                        {"to":   user}
                    ]
                })
                .sort("timestamp", 1)
        )
        history = [ self._serialise(m) for m in msgs ]
        emit("history", history)

    def on_message(self, data):
        # Persist the message
        self._db().messages.insert_one({
            **data,
            "timestamp": datetime.datetime.utcnow()
        })
        # Broadcast to **all** clients in the room, including sender
        emit("message", data, room=data["room"], include_self=True)