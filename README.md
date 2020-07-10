
# @julpy/oauth2-connect

[![GitHub license](https://img.shields.io/github/license/co-demos/oauth2-connect)](https://github.com/co-demos/oauth2-connect/blob/master/LICENSE) [![npm (scoped)](https://img.shields.io/npm/v/@julpy/oauth2-connect.svg)](https://www.npmjs.com/package/@julpy/vue-loauth) [![npm bundle size (minified)](https://img.shields.io/bundlephobia/min/@julpy/oauth2-connect.svg)](https://www.npmjs.com/package/@julpy/oauth2-connect)

Login with Oauth2 from a vue app (or not) ... without any dependencies

---------

## Install

```terminal
npm install @julpy/oauth2-connect

... or for beta versions

npm install @julpy/oauth2-connect@0.0.1-beta.1
```

---------

## Usage as vue plugin

### in your vue app's `.env` file

```env
### OAUTH VARS
VUE_APP_DEFAULT_CLIENT_ID=my-oauth-client-id
VUE_APP_DEFAULT_CLIENT_SECRET=my-oauth-secret-string
VUE_APP_OAUTH_SERVER=https://my-oauth-server.com/fr/oauth
VUE_APP_OAUTH_SCOPE=default
VUE_APP_OAUTH_REDIRECT=/login
VUE_APP_OAUTH_FLOW=pkce

### settings for localStorage
VUE_APP_OAUTH_STATE_NAME=dgfState
VUE_APP_OAUTH_CODE_VERIFIER_NAME=dgfCodeVerif
VUE_APP_OAUTH_ACCESS_TOKEN_NAME=dgfAccessToken
VUE_APP_OAUTH_REFRESH_TOKEN_NAME=dgfRefreshToken

```

### in your vue app's `main.js` file

```js
import OAUTHcli from '@julpy/oauth2-connect'

...

const isDevMode = Boolean(process.env.VUE_APP_DEV_MODE)

const oauthOptions = {
  storeModuleName: 'oauth',

  clientId: isDevMode && process.env.VUE_APP_DEFAULT_CLIENT_ID,
  clientSecret: isDevMode && process.env.VUE_APP_DEFAULT_CLIENT_SECRET,

  oauthServer: process.env.VUE_APP_OAUTH_SERVER,
  oauthFlow: process.env.VUE_APP_OAUTH_FLOW,
  oauthScope: process.env.VUE_APP_OAUTH_SCOPE,
  oauthRedirect: process.env.VUE_APP_OAUTH_REDIRECT,

  stateName: process.env.VUE_APP_OAUTH_STATE_NAME,
  codeVerifierName: process.env.VUE_APP_OAUTH_CODE_VERIFIER_NAME,
  oauthAccessTokenName: process.env.VUE_APP_OAUTH_ACCESS_TOKEN_NAME,
  oauthRefreshTokenName: process.env.VUE_APP_OAUTH_REFRESH_TOKEN_NAME
}
Vue.use(OAUTHcli, oauthOptions, store)

...

```

