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

// private endpoint under root "/"
export const PRIVATE_INFO_ENDPOINT = "/me"



/*******************************/
/******* Client *******/
/*******************************/
export const CLIENT_PORT = 8080
export const CLIENT_HOST = "http://localhost"
export const CLIENT_CALLBACK_PATH = `/callback`
export const CLINET_ID = "123"
export const CLIENT_SECRET = "123"