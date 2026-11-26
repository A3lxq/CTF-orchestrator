"""
A tiny fake of a cloud Secrets Manager, bound to 127.0.0.1:8600 only --
never published, reachable solely via the main app's /fetch SSRF. No
real request-signing is implemented (same deliberate simplification as
cloudbreak-noob-bucket's own hand-rolled s3server.py): it just checks
the caller supplied the AccessKeyId stolen from the fake IMDS above, as
an ?AccessKeyId= query parameter rather than a signed Authorization
header -- a plain GET-based SSRF proxy like the main app's /fetch can't
forward arbitrary request headers, so the "credential" has to travel in
the URL itself, which is exactly what a real pre-signed URL would look
like anyway.
"""
import os
from flask import Flask, request, Response

from generate_flags import flag_for

SECRET = os.environ["CTF_SECRET"]
EXPECTED_ACCESS_KEY_ID = "AKIANIMBUSDEPLOY01"
# Fixed/narrative -- identical for every team, the same way every other
# box's discoverable credential is. What varies per team is flag6 itself.
SSH_PASSWORD = "NimbusDeploy-Rotate-Me-42!"

app = Flask(__name__)


@app.route("/secretsmanager/get-secret-value")
def get_secret_value():
    secret_id = request.args.get("SecretId", "")
    access_key_id = request.args.get("AccessKeyId", "")
    if access_key_id != EXPECTED_ACCESS_KEY_ID:
        return Response("AccessDeniedException: no valid credential supplied", status=403)
    if secret_id != "nimbus/prod/ssh":
        return Response("ResourceNotFoundException: secret not found", status=404)
    return {
        "Name": secret_id,
        "SecretString": f'{{"username": "svc-deploy", "password": "{SSH_PASSWORD}"}}',
        "Note": f"Flag 6: {flag_for(SECRET, 6)}",
    }


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8600)
