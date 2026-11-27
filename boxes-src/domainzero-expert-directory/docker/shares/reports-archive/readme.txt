Reports Archive -- svc-reports-authenticated access only
==========================================================
If you can read this, you've authenticated as svc-reports (or
Administrator). That means a password reset by someone other than
svc-reports itself actually took effect -- which should not have been
possible under a correctly configured directory ACL. This share's own
SMB session authentication is the real proof: there's no other way to
reach it with svc-reports's identity.

Archive flag: FLAG6_PLACEHOLDER

See quarterly-notes.txt for what svc-reports has access to review.
