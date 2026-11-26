
"""Firebase Admin SDK connection for DataLineage AI."""

from functools import lru_cache
from pathlib import Path

import firebase_admin
from firebase_admin import credentials, firestore

from .config import settings


@lru_cache(maxsize=1)
def get_firebase_app():
    project_id = settings.firebase_project_id
    credentials_path = settings.firebase_credentials_path

    if not project_id or not credentials_path:
        raise RuntimeError("Firebase configuration is missing")

    path = Path(credentials_path).expanduser()

    if not path.is_file():
        raise RuntimeError("Firebase service-account file not found")

    try:
        app = firebase_admin.get_app()

        if app.project_id != project_id:
            raise RuntimeError("Firebase project ID mismatch")

        return app

    except ValueError:
        certificate = credentials.Certificate(str(path))

        return firebase_admin.initialize_app(
            certificate,
            {"projectId": project_id},
        )


def get_firestore_client():
    return firestore.client(app=get_firebase_app())


def check_firestore_connection():
    client = get_firestore_client()

    client.collection("_connection_checks").document("backend").set(
        {"status": "connected"},
        merge=True,
    )

    return True
