"""
A deliberately minimal, real-enough-to-be-convincing fake of a cloud
provider's legacy (unauthenticated) instance metadata service. Bound to
169.254.169.254:80 -- the real link-local address every major cloud
uses for this, added to this container's own loopback interface by
entrypoint.sh (needs NET_ADMIN). Never published as a front-door port,
so it's reachable only via the main app's /fetch SSRF -- exactly the
real-world "SSRF to cloud IMDS" attack this box is modeling.
"""
import os
from flask import Flask, Response

from generate_flags import flag_for

SECRET = os.environ["CTF_SECRET"]
ROLE_NAME = "nimbus-deploy-role"
ACCESS_KEY_ID = "AKIANIMBUSDEPLOY01"

app = Flask(__name__)


@app.route("/latest/meta-data/iam/security-credentials/")
def list_role():
    # flag4: just finding this role name via the metadata service.
    return Response(f"{ROLE_NAME}\n\n(Flag 4: {flag_for(SECRET, 4)})\n", mimetype="text/plain")


@app.route(f"/latest/meta-data/iam/security-credentials/{ROLE_NAME}")
def role_credentials():
    # flag5: the stolen temporary credentials themselves. AccessKeyId is
    # fixed (an identifier, not a secret, same as this box's other fixed
    # narrative details) -- the SecretAccessKey is what actually varies
    # per team, and is what the fake Secrets Manager checks for below.
    return {
        "Code": "Success",
        "LastUpdated": "2026-10-01T00:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": ACCESS_KEY_ID,
        "SecretAccessKey": flag_for(SECRET, 5),
        "Token": "irrelevant-session-token",
        "Expiration": "2099-01-01T00:00:00Z",
    }


if __name__ == "__main__":
    app.run(host="169.254.169.254", port=80)
