import express, { NextFunction, Request, Response } from "express"
import { authenticateMiddleware, getMetadataJson, handleGetAuthorize, handlePostTokenRevocation as handleGetRevoke, handleGetProtectedEndpoint as handleGetProtectedEndpoint, handlePostAuthorize, handlePostToken, REQUIRED_SCOPE, addDummyData, } from "./oauth.js"
import { launchClient } from "./sampleClient.js"
import { AUTHORIZE_ENDPOINT, OAUTH_ROUTER_ENDPOINT, OTHER_ERROR_ENDPOINT, PRIVATE_INFO_ENDPOINT as PROTECTED_ENDPOINT, REVOCATION_ENDPOINT, SERVER_PORT, TOKEN_ENDPOINT } from "./constants.js"




/*******************************/
/******* Endpoint Set Up *******/
/*******************************/

const app = express()
app.use(express.json())
app.use(express.urlencoded({extended: false}))

const oauthRouter = express.Router()

// Get /oauth/authorize
// Since we only want to authorize on Post AUTHORIZE_ENDPOINT
// either redirect to a login endpoint or
// Show login form/registration from in this endpoint
// to collect user credentials and post to `AUTHORIZE_ENDPOINT` with the same query parameters
oauthRouter.get(AUTHORIZE_ENDPOINT, async (req: Request, res: Response) => {
    handleGetAuthorize(req, res)
})

// actual authorization
oauthRouter.post(AUTHORIZE_ENDPOINT, async (req: Request, res: Response) => {
    handlePostAuthorize(req, res)
})

// error endpoint
// show authorization error when redirect uri missing
oauthRouter.get(OTHER_ERROR_ENDPOINT, async (req: Request, res: Response) => {
    let error = req.query.error  ?? "unknown error"
    res.render("error.ejs", {
        errorMessage: `${error}`
    })
})

// token exchange
// - access token if grant_type is authorization_code
// - refresh token if grant_type is refresh_token
// (automatically handled by OAuth2Server
oauthRouter.post(TOKEN_ENDPOINT, async (req: Request, res: Response) => {
    handlePostToken(req, res)
})

oauthRouter.post(REVOCATION_ENDPOINT, async (req: Request, res: Response) => {
    handleGetRevoke(req, res)
})

app.use(OAUTH_ROUTER_ENDPOINT, oauthRouter)

// Authorization Server Metadata endpoint
// specification: https://datatracker.ietf.org/doc/html/rfc8414
// either /.well-known/openid-configuration or /.well-known/oauth-authorization-server will work
const OAUTH_METADATA_ENDPOINT = "/.well-known/oauth-authorization-server"
const OPENID_METADATA_ENDPOINT = "/.well-known/openid-configuration"
app.get(OAUTH_METADATA_ENDPOINT, async (req: Request, res: Response) => {
    getMetadataJson(req, res)
})
app.get(OPENID_METADATA_ENDPOINT, async (req: Request, res: Response) => {
    getMetadataJson(req, res)
})


// some protected resource
app.get(PROTECTED_ENDPOINT, async (req: Request, res: Response, next: NextFunction) => {
    await authenticateMiddleware(req, res, next, [REQUIRED_SCOPE])
}, async (req: Request, res: Response) => {
    handleGetProtectedEndpoint(req, res)
})

async function main() {
    app.listen(SERVER_PORT, () => {
        console.log(`Server listening on port ${SERVER_PORT}`)
    })

    // add some dummy data for testing
    addDummyData()

    // start dummy client
    launchClient().catch((error) => {
        console.error("Fatal error while running client:", error)
    })

    process.on('SIGINT', async () => {
        console.log('Shutting down server...')
        process.exit(0)
    })
}

main()