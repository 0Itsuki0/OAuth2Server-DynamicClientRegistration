/*******************************/
/******* Server *******/
/*******************************/
export const SERVER_PORT = 3000
export const SERVER_HOST = "http://localhost"

export const OAUTH_ROUTER_ENDPOINT = "/oauth"

// endpoints under OAUTH_ROUTER_ENDPOINT "/oauth"
export const AUTHORIZE_ENDPOINT = "/authorize"
export const TOKEN_ENDPOINT = "/token"
export const OTHER_ERROR_ENDPOINT = "/error"
export const REVOCATION_ENDPOINT = "/logout"
export const REGISTRATION_ENDPOINT = "/register"


// Some configuration
export const AUTH_METHODS = ["client_secret_basic", "client_secret_post"]
export const GRANT_TYPES = ["authorization_code", "refresh_token"]
export const REQUIRED_SCOPES = ["email"]
export const RESPONSE_TYPES = ["code"]
export const CODE_CHALLENGE_METHODS = ["S256"]
export const ACCESS_TOKEN_LIFETIME = 60*60
export const REFRESH_TOKEN_LIFETIME = 60*60*24*14


// private endpoint under root "/"
export const PROTECTED_ENDPOINT = "/me"



/*******************************/
/******* Client *******/
/*******************************/
export const CLIENT_PORT = 8080
export const CLIENT_HOST = "http://localhost"
export const CLIENT_CALLBACK_PATH = `/callback`