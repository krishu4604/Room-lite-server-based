"""Dedicated remote deployment; no changes to the original Room Lite server."""
import os

from licensing.bootstrap import prepare
from licensing.service import create_app
from licensing.public_ids import PublicIds
from licensing.remote_api import register_remote


def application(root=None, gateway_factory=None, store=None, public_ids=None):
    if root is None and store is None:
        root = prepare()
    if gateway_factory is None:
        from backend.room_service import RoomService
        gateway_factory = RoomService
    public_ids = public_ids or PublicIds()
    app = create_app(root=root, gateway_factory=gateway_factory, store=store, public_ids=public_ids)
    register_remote(app, gateway_factory, public_ids)
    return app


if __name__ == '__main__':
    if os.name == 'nt':
        raise SystemExit('Use the Flask development server on loopback for local tests; use Gunicorn on Render.')
    os.execvp('gunicorn', ['gunicorn','licensing.remote_bootstrap:application()', '--bind',
                          '0.0.0.0:' + os.environ.get('PORT','8080'), '--workers','1','--threads','8','--timeout','45'])
