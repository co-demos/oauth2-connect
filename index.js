// npm package : oauth2-connect

const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const charactersPunctuation = '-._~'
const flowsMinMax = {
  pkce: {
    needExchange: true,
    state: { min: 28, max: 32, chars: [...characters] },
    code: { min: 43, max: 128, chars: [...characters, ...charactersPunctuation] }
  },
  authCode: {
    needExchange: true,
    state: { min: 28, max: 32, chars: characters }
  },
  implicit: {
    needExchange: false,
    state: { min: 28, max: 32, chars: characters }
  }
}
const basicHeaders = {
  Accept: 'application/json',
  'Content-Type': 'application/json'
}

/**
 * RANDOMIZATION UTILS FUNCTIONS
 */

function randomFloat () {
  const int = window.crypto.getRandomValues(new Uint32Array(1))[0]
  return int / 2 ** 32
}

function randomInt (min, max) {
  const range = max - min
  return Math.floor(randomFloat() * range + min)
}

function randomIntArray (length, min, max) {
  return new Array(length).fill(0).map(() => randomInt(min, max))
}

// random string based on window.crypto given a string lenght, a specs.min, a specs.max, and an array of chars to choose from
function generateRandomString (stringLength, specs) {
  let randomStringAsArray = randomIntArray(stringLength, specs.min, specs.max)
  randomStringAsArray = randomStringAsArray.map(dec => {
    const randomIndex = randomInt(0, specs.chars.length - 1)
    return specs.chars[randomIndex]
  })
  return randomStringAsArray.join('')
}

function sha256 (plain) {
  const encoder = new TextEncoder()
  const data = encoder.encode(plain)
  return window.crypto.subtle.digest('SHA-256', data)
}

function base64urlencode (str) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function pkceChallengeFromVerifier (v) {
  const hashed = await sha256(v)
  return base64urlencode(hashed)
}

/**
 * MAIN OAUTH CLASS
 */
class OAuthLib {
  constructor (options, store) {
    this.store = store
    this.storeModuleName = options.storeModuleName
    // console.log('>>> OAuthLib > init >  store :', store)

    // set OAUTH clientId - both in class and vuex module
    this.clientId = options.clientId
    this.clientSecret = options.clientSecret
    this.store.commit(`${this.storeModuleName}/setClientId`, this.clientId)
    this.store.commit(`${this.storeModuleName}/setClientSecret`, this.clientSecret)

    // set OAUTH main urls - both in class and vuex module
    this.oauthServer = options.oauthServer
    this.authPath = options.authPath ? options.authPath : '/authorize'
    this.tokenPath = options.tokenPath ? options.tokenPath : '/token'
    this.revokePath = options.revokePath ? options.revokePath : '/revoke'
    this.redirect = options.oauthRedirect ? options.oauthRedirect : '/login'
    this.redirectURI = encodeURIComponent(`${this._getBaseUrl()}${this.redirect}`)
    this.redirectHomeURI = encodeURIComponent(`${this._getBaseUrl()}`)
    this.store.commit(`${this.storeModuleName}/setOauthRedirect`, this.redirect)
    this.store.commit(`${this.storeModuleName}/setOauthRedirectURI`, this.redirectURI)

    // set OAUTH options
    this.oauthFlow = options.oauthFlow // could be pkce | auth_code | implicit
    this.oauthScope = options.oauthScope ? options.oauthScope : 'default'

    // set OAUTH localStorage object names : state | code_verifier | access_token | refresh_token
    this.stateName = options.stateName ? options.stateName : 'state'
    this.codeVerifierName = options.codeVerifierName ? options.codeVerifierName : 'code_verifier'
    this.oauthAccessTokenName = options.oauthAccessTokenName ? options.oauthAccessTokenName : 'accessToken'
    this.store.commit(`${this.storeModuleName}/setTokenName`, { type: 'access', name: this.oauthAccessTokenName })
    this.oauthRefreshTokenName = options.oauthRefreshTokenName ? options.oauthRefreshTokenName : 'refreshToken'
    this.store.commit(`${this.storeModuleName}/setTokenName`, { type: 'refresh', name: this.oauthRefreshTokenName })

    // set flowSpecs
    this.flowSpecs = flowsMinMax[this.oauthFlow]

    // debugging
    console.log('>>> OAuthLib > init >  this :', this)
  }

  _getBaseUrl () {
    const port = window.location.port
    return window.location.protocol + '//' + window.location.hostname + (port ? ':' + port : '')
  }

  createNewState () {
    const stateLength = randomInt(this.flowSpecs.state.min, this.flowSpecs.state.max)
    const state = generateRandomString(stateLength, this.flowSpecs.state)
    localStorage[this.stateName] = state
    return state
  }

  getStateFromLocalStorage () {
    return localStorage[this.stateName]
  }

  getCodeVerifierFromLocalStorage () {
    return localStorage[this.codeVerifierName]
  }

  // >>> TODO: handle expiration
  isAuthenticated () {
    return !!localStorage[this.oauthAccessTokenName]
  }

  /**
   * WORKFLOWS OBJECTS
  */
  async buildAuthWorkflowObject (clientId, state, code) {
    // console.log('>>> OAuthLib > buildAuthWorkflowObject >  clientId :', clientId)
    const wf = {
      flow: this.oauthFlow,
      oauthExchangeUrl: '',
      oauthExchangeData: {}
    }

    // declare some vars
    const codeVerifier = this.getCodeVerifierFromLocalStorage()

    // set exchange callbacks common vars
    wf.oauthExchangeUrl = `${this.oauthServer}${this.tokenPath}`
    wf.oauthExchangeData = {
      grant_type: 'authorization_code',
      client_id: `${this.clientId}`,
      client_secret: `${this.clientSecret}`,
      redirect_uri: `${this.redirectHomeURI}`,
      code: `${code}`,
      code_verifier: `${codeVerifier}`
    }

    // return workflow data
    const partialWorkflow = (({ oauthExchangeUrl, oauthExchangeData }) => ({ oauthExchangeUrl, oauthExchangeData }))(wf)
    return partialWorkflow
  }

  async buildLoginWorkflowObject (clientId, state) {
    // console.log('>>> OAuthLib > buildLoginWorkflowObject >  clientId :', clientId)
    // console.log('>>> OAuthLib > buildLoginWorkflowObject >  redirectURI :', redirectURI)
    const encodedState = encodeURIComponent(state)
    const wf = {
      flow: this.oauthFlow,
      oauthLogin: `${this.oauthServer}${this.authPath}?`,
      stringsLogin: {
        stateString: `state=${encodedState}`,
        clientIdString: `client_id=${clientId}`,
        scopeString: `scope=${this.oauthScope}`,
        redirectUri: `redirect_uri=${this.redirectURI}`,
        respTypeString: 'response_type=token'
      },
      loginUrlString: ''
    }

    // declare some vars
    let codeVerifLength, codeVerifier, codeChallenge

    switch (this.oauthFlow) {
      // case 'implicit':
      //   break
      // case 'authCode':
      //   break
      case 'pkce':
        wf.stringsLogin.respTypeString = 'response_type=code'
        // generate code verifier and code challenge
        wf.stringsLogin.codeChallengeMethod = 'code_challenge_method=S256'
        codeVerifLength = randomInt(this.flowSpecs.code.min, this.flowSpecs.code.max)
        codeVerifier = generateRandomString(codeVerifLength, this.flowSpecs.code)
        localStorage[this.codeVerifierName] = codeVerifier
        codeChallenge = await pkceChallengeFromVerifier(codeVerifier)
        wf.stringsLogin.codeChallenge = `code_challenge=${codeChallenge}`
        break
    }

    // build login url as concatenated string
    wf.loginUrlString = `${wf.oauthLogin}${Object.values(wf.stringsLogin).join('&')}`

    // return workflow data
    const partialWorkflow = (({ loginUrlString }) => ({ loginUrlString }))(wf)
    return partialWorkflow
  }

  /**
   * Launches the login workflow
   */
  async login (clientId) {
    if (clientId) { this.clientId = clientId }
    console.log('>>> OAuthLib > login >  this.clientId :', this.clientId)

    // create a new state to send in request and store for later checks
    const state = this.createNewState()

    // build the workflow data object
    const workflowData = await this.buildLoginWorkflowObject(this.clientId, state)
    console.log('>>> OAuthLib > login >  workflowData :', workflowData)
    console.log('>>> OAuthLib > login >  workflowData.loginUrlStrings :', workflowData.loginUrlString)

    // open url in browser
    window.location = workflowData.loginUrlString
  }

  /**
   * Handle the response from the login workflow
   */
  async retrieveToken () {
    const state = this.getStateFromLocalStorage()
    console.log('>>> OAuthLib > retrieveToken >  state :', state)

    // build the query dict
    const queryObject = {}
    window.location.search.substr(1).split('&').forEach(item => {
      queryObject[item.split('=')[0]] = item.split('=')[1]
    })
    console.log('>>> OAuthLib > retrieveToken > queryObject :', queryObject)

    // check state from url against workflow.sate
    const areStatesSame = queryObject.state === state
    if (!areStatesSame) {
      window.alert('>>> OAuthLib > retrieveToken >  states are not the same ')
      return
    } else {
      console.log('>>> OAuthLib > retrieveToken >  states are the same ... continue')
    }

    // declare some empty vars
    const code = queryObject.code
    const workflowData = await this.buildAuthWorkflowObject(this.clientId, state, code)
    const exchangeUrl = workflowData.oauthExchangeUrl
    const exchangeData = workflowData.oauthExchangeData
    console.log('>>> OAuthLib > retrieveToken > workflowData :', workflowData)

    let accessToken, refreshToken, expiresIn, tokenType

    // extract code from response
    if (this.flowSpecs.needExchange) {
      // for : pkce | authorisation_code
      const headerStr = btoa(`${this.clientId}:${this.clientSecret}`)
      const config = {
        method: 'POST',
        headers: { Authorization: `Basic ${headerStr}` },
        // headers: { ...basicHeaders, Authorization: `Basic ${headerStr}` },
        body: JSON.stringify(exchangeData)
      }
      const response = await fetch(exchangeUrl, config)
      accessToken = response.body.access_token
      refreshToken = response.body.refreshToken
      expiresIn = response.body.expires_in
      tokenType = response.body.token_type
    } else {
      // for : implicit
      accessToken = queryObject.access_token
      refreshToken = queryObject.refresh_token
      expiresIn = queryObject.expires_in
      tokenType = queryObject.token_type
    }

    // set localStorage
    localStorage[this.oauthAccessTokenName] = accessToken
    localStorage[this.oauthRefreshTokenName] = refreshToken
    localStorage[`${this.oauthAccessTokenName}Expires`] = expiresIn
    localStorage[`${this.oauthAccessTokenName}tokenType`] = tokenType
    this.store.commit(`${this.storeModuleName}/setToken`, { type: 'access', token: accessToken })
    this.store.commit(`${this.storeModuleName}/setToken`, { type: 'refresh', token: refreshToken })
  }

  /**
   * Run the logout
   */
  async logout () {
    const revokeUrl = `${this.oauthServer}${this.revokePath}`
    console.log('>>> OAuthLib > logout >  revokeUrl :', revokeUrl)
    const data = { token: localStorage[this.oauthAccessTokenName] }
    const config = {
      method: 'POST',
      headers: basicHeaders,
      body: JSON.stringify(data)
    }
    try {
      await fetch(revokeUrl, config)
    } catch (error) {
      console.log('error', error)
    } finally {
      delete localStorage[this.stateName]
      delete localStorage[this.codeVerifierName]
      delete localStorage[this.oauthAccessTokenName]
      delete localStorage[`${this.oauthAccessTokenName}Expires`]
      delete localStorage[`${this.oauthAccessTokenName}tokenType`]
    }
  }
}

/**
 * VUE STORE
 */
// vue store module within plugin just for auth
export const moduleAuth = {
  namespaced: true,
  state: () => ({
    oauthServer: process.env.VUE_APP_OAUTH_SERVER,
    oauthFlow: process.env.VUE_APP_OAUTH_FLOW,
    oauthScope: process.env.VUE_APP_OAUTH_SCOPE,

    clientId: undefined,
    clientSecret: undefined,
    oauthRedirect: undefined,

    tokens: {
      access: { name: '', value: undefined },
      refresh: { name: '', value: undefined }
    }

  }),
  getters: {
    isAuthenticated: (state) => {
      // TODO: handle expiration
      return !!this.oauthToken
    }
  },
  mutations: {

    // client-related
    setClientState (state, clientState) {
      state.clientState = clientState
    },
    setClientId (state, clientId) {
      state.clientId = clientId
    },
    setClientSecret (state, clientSecret) {
      state.clientSecret = clientSecret
    },

    // redirection
    setOauthRedirect (state, oauthRedirect) {
      state.oauthRedirect = oauthRedirect
    },
    setOauthRedirectURI (state, oauthRedirectURI) {
      state.oauthRedirectURI = oauthRedirectURI
    },

    // token-related
    setTokenName (state, { type, name }) {
      state.tokens[type].name = name
    },
    setToken (state, { type, token }) {
      state.tokens[type].value = token
    },
    resetToken (state) {
      state.tokens = {}
    }
  },
  actions: {},
  modules: {}
}

/**
 * OAUTH CLIENT - PLUGIN FOR VUE
 */
// wrap up client
const OAUTHcli = {
  install (Vue, options, store) {
    // register namespaced store
    const moduleName = options.storeModuleName ? options.storeModuleName : 'oauth'
    options.storeModuleName = moduleName
    store.registerModule(moduleName, moduleAuth)

    // declare client as a global prototype in Vue
    Vue.prototype.$OAUTHcli = new OAuthLib(options, store)
  }
}
export default OAUTHcli

// // Automatic installation if Vue has been added to the global scope.
// if (typeof window !== 'undefined' && window.Vue) {
//   window.Vue.use(OAUTHcli)
// }
