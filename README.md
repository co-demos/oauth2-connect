
# @julpy/oauth2-connect

[![GitHub license](https://img.shields.io/github/license/co-demos/oauth2-connect)](https://github.com/co-demos/oauth2-connect/blob/master/LICENSE) [![npm (scoped)](https://img.shields.io/npm/v/@julpy/oauth2-connect.svg)](https://www.npmjs.com/package/@julpy/oauth2-connnect) [![npm bundle size (minified)](https://img.shields.io/bundlephobia/min/@julpy/oauth2-connect.svg)](https://www.npmjs.com/package/@julpy/oauth2-connect)

Login with Oauth2 from a vue app (or not) ... without any dependencies (except `pkce` but don't freak out it's a little one)

---------

## Install

```terminal
npm install @julpy/oauth2-connect

... or for beta versions

npm install @julpy/oauth2-connect@0.0.1-beta.2
```

---------

## Usage as vue plugin

To use `oauth2-connect` in your vue app you will have to follow those steps... 

### 1. in your vue app's `.env` file

```env
### OAUTH client settings
VUE_APP_DEFAULT_CLIENT_ID=my-oauth-client-id
VUE_APP_DEFAULT_CLIENT_SECRET=my-oauth-secret-string

### OAUTH server settings
VUE_APP_OAUTH_SERVER=https://my-oauth-server.com/fr/oauth
VUE_APP_OAUTH_SCOPE=default
VUE_APP_OAUTH_REDIRECT=/login
VUE_APP_OAUTH_FLOW=pkce

### settings for localStorage
VUE_APP_OAUTH_LS_PREFIX=dgf

```

### 2. in any of your vue app's `main.js` file

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

  localStoragePrefix: process.env.VUE_APP_OAUTH_PREFIX // here prefix is `dgf`
}
Vue.use(OAUTHcli, oauthOptions, store)

...

```

### 3. in a vue component

```js
<script>
import { mapState } from 'vuex'

export default {
  name: 'Login',
  data () {
    return {}
  },
  async mounted () {
    console.log('-V- LOGIN > mounted ...')
    try {
      await this.$OAUTHcli.retrieveToken()
      const authOptions = {
        bearerAuth: this.tokens.access.value
      }
      console.log('-V- LOGIN > created > authOptions :', authOptions)
      // do whatever you want with token this now...
    } catch (ex) {
      console.log('error', ex)
    }
  }
}
</script>
```
