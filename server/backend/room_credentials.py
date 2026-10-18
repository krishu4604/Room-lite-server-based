"""Resolve native gateway auth from this account's existing auth store.

The app maps v1 userSession to OAuth token, v2 userSession to access token.
userToken is a separate, optional cached gateway token, not the OAuth token.
"""


def gateway_credentials(account):
    try:
        uid = int(account.get('uid') or account.get('id') or 0)
    except (TypeError, ValueError):
        raise ValueError('Selected account does not have a valid numeric UID') from None
    version = str(account.get('oauth_version') or 'v1').lower()
    if version == 'v2':
        session = account.get('access_token') or ''
    elif version == 'v1':
        session = account.get('oauth_token') or ''
    else:
        raise ValueError('Unsupported account authentication version; log in again')
    device = account.get('device_id') or ''
    if uid <= 0 or not session or not device:
        raise ValueError('Selected account is missing login credentials or device ID; log in again')
    token = account.get('gateway_user_token') or account.get('gateway_token') or ''
    return uid, str(session), str(token), str(device)
