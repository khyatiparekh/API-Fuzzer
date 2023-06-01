import jwt
import binascii
import json
import base64
from termcolor import colored

def check_jwt_configuration(jwt_token):
    """
    This function decodes a JWT token and checks its configuration.

    :param jwt_token: JWT token to decode.
    :return: None
    """
    print(colored("\n\n[#] JWT Information", 'cyan'))

    # Split the JWT token into header, payload, and signature
    segments = jwt_token.split('.')

    if len(segments) != 3:
        print(colored("[-] Invalid token. Please check your JWT token.", 'red'))
        return

    try:
        # Decode the header, payload, and signature from base64
        header = base64.urlsafe_b64decode(segments[0] + "==")
        payload = base64.urlsafe_b64decode(segments[1] + "==")
        signature = base64.urlsafe_b64decode(segments[2] + "==")

        # Convert from json to a python dictionary
        header = json.loads(header)
        payload = json.loads(payload)

        # Handle more potential errors in decoding
    except (binascii.Error, ValueError) as e:
        print(colored(f"[-] Error decoding JWT: {e}", 'red'))
        return

    # Header
    print(colored("\n[*] JWT Header: ", 'light_magenta'), header)
    if 'alg' in header:
        print(colored("alg:", 'green'), colored(f"{header['alg']}", 'light_yellow'), "- The 'alg' field represents the hashing algorithm used for the JWT token. Misconfiguration can lead to security vulnerabilities. For instance, if it is set to 'none', it means the token will be unsecured. Other insecure algorithms include HS256 with a weak key.")

    if 'typ' in header:
        print(colored("typ:", 'green'), colored(f"{header['typ']}", 'light_yellow'), " - The 'typ' field represents the type of token. It should always be 'JWT'. If it's not, it might imply a different token processing strategy which could introduce vulnerabilities.")

    # Payload
    print(colored("\n[*] JWT Payload: ", 'light_magenta'), payload)
    if 'sub' in payload:
        print(colored("sub:", 'green'), colored(f"{payload['sub']}", 'light_yellow'), " - The 'sub' field represents the subject of the token. If this is manipulated, it could impersonate a different user.")
    if 'name' in payload:
        print(colored("name:", 'green'), colored(f"{payload['name']}", 'light_yellow'), " - The 'name' field represents the name of the user. Manipulating this could misrepresent the user's identity.")
    if 'iat' in payload:
        print(colored("iat:", 'green'), colored(f"{payload['iat']}", 'light_yellow'), " - The 'iat' field represents the timestamp of when the token was issued. An attacker could use an old token if the 'iat' value is not properly checked.")
    if 'exp' in payload:
        print(colored("exp:", 'green'), colored(f"{payload['exp']}", 'light_yellow'), " - The 'exp' field represents the timestamp of when the token will expire. If this is set too far in the future, it could allow an attacker to use a stolen token for a prolonged period.")
    if 'aud' in payload:
        print(colored("aud:", 'green'), colored(f"{payload['aud']}", 'light_yellow'), " - The 'aud' field represents the intended audience of the token. If this is not correctly set or not verified, it could lead to tokens intended for one service being used against another.")
    if 'iss' in payload:
        print(colored("iss:", 'green'), colored(f"{payload['iss']}", 'light_yellow'), " - The 'iss' field represents the issuer of the token. If the issuer is not a trusted entity or is not verified, it could lead to acceptance of tokens from unauthorized issuers.")
    if 'nbf' in payload:
        print(colored("nbf:", 'green'), colored(f"{payload['nbf']}", 'light_yellow'), " - The 'nbf' field represents the timestamp before which the token must not be accepted. If this is not properly enforced, it could allow premature use of a token.")
    if 'jti' in payload:
        print(colored("jti:", 'green'), colored(f"{payload['jti']}", 'light_yellow'), " - The 'jti' field is a unique identifier for the token, which can be used to prevent the token from being replayed. If it's not used, an attacker could replay the token multiple times.")
    if 'azp' in payload:
        print(colored("azp:", 'green'), colored(f"{payload['azp']}", 'light_yellow'), " - The 'azp' field represents the authorized party - the party to which the ID Token was issued. If present, it must contain the OAuth 2.0 Client ID of this party.")
    if 'scope' in payload:
        print(colored("scope:", 'green'), colored(f"{payload['scope']}", 'light_yellow'), " - The 'scope' field represents the scopes that this token has access to. Be cautious of tokens with broad or powerful scopes.")
    if 'acr' in payload:
        print(colored("acr:", 'green'), colored(f"{payload['acr']}", 'light_yellow'), " - The 'acr' field represents the Authentication Context Class Reference. It can be used to differentiate between different authentication methods used during token issuance.")

    # Signature
    print(colored("\n[*] JWT Signature: ", 'light_magenta'), signature)