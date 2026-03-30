from flask import Blueprint

kb_bp = Blueprint('kb', __name__)

from kb import routes  # noqa: E402, F401
