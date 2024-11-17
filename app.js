const express = require('express')
const app = express()

app.use(express.json())

const {open} = require('sqlite')
const sqlite3 = require('sqlite3')

const bcrypt = require('bcrypt')

const jwt = require('jsonwebtoken')

const path = require('path')

let db = null
const initializingDbAndServer = async () => {
  try {
    db = await open({
      filename: path.join(__dirname, 'covid19IndiaPortal.db'),
      driver: sqlite3.Database,
    })
    app.listen(3000, () =>
      console.log('Server Up and Running at http://localhost:3000/'),
    )
  } catch (error) {
    console.log(`Db Error:${error}`)
    process.exit(1)
  }
}

initializingDbAndServer()

//API-1
app.post('/login/', async (request, response) => {
  const {username, password} = request.body

  const checkUsernameQuery = `
        SELECT *
        FROM user
        WHERE username LIKE '${username}';
    `

  const userDetails = await db.get(checkUsernameQuery)

  if (userDetails === undefined) {
    response.status(400)
    response.send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      userDetails.password,
    )
    if (isPasswordMatched === false) {
      response.status(400)
      response.send('Invalid password')
    } else {
      const payload = {
        username: username,
      }
      const jwtToken = jwt.sign(payload, 'My_secret_key')
      response.send({jwtToken: jwtToken})
    }
  }
})

//Authentication Middleware
const authenticationMiddleware = (request, response, next) => {
  let jwtToken
  const authHeader = request.headers['authorization']
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }

  if (jwtToken === undefined) {
    response.status(401)
    response.send('Invalid JWT Token')
  } else {
    jwt.verify(jwtToken, 'My_secret_key', (error, payload) => {
      if (error) {
        response.status(401)
        response.send('Invalid JWT Token')
      } else {
        next()
      }
    })
  }
}

//API-2
app.get('/states/', authenticationMiddleware, async (request, response) => {
  const getStatesQuery = `
        SELECT *
        FROM state;
    `
  const states = await db.all(getStatesQuery)
  const allStates = states.map(eachState => ({
    stateId: eachState.state_id,
    stateName: eachState.state_name,
    population: eachState.population,
  }))
  response.send(allStates)
})

module.exports = app

//API-3
app.get(
  '/states/:stateId/',
  authenticationMiddleware,
  async (request, response) => {
    const {stateId} = request.params
    const getStateQuery = `
        SELECT * 
        FROM state
        WHERE state_id = ${stateId};
    `
    const state = await db.get(getStateQuery)
    const stateDetails = {
      stateId: state.state_id,
      stateName: state.state_name,
      population: state.population,
    }
    response.send(stateDetails)
  },
)

//API-4
app.post('/districts/', authenticationMiddleware, async (request, response) => {
  const {districtName, stateId, cases, cured, active, deaths} = request.body
  const addDistrictQuery = `
        INSERT INTO district
            (district_name,state_id,cases,cured,active,deaths)
        VALUES
            ('${districtName}',${stateId},${cases},${cured},${active},${deaths});
    `
  await db.run(addDistrictQuery)
  response.send('District Successfully Added')
})

//API-5
app.get(
  '/districts/:districtId/',
  authenticationMiddleware,
  async (request, response) => {
    const {districtId} = request.params
    const getDistrictQuery = `
        SELECT *
        FROM district
        WHERE district_id = ${districtId};
    `
    const district = await db.get(getDistrictQuery)
    const districtDetails = {
      districtId: district.district_id,
      districtName: district.district_name,
      stateId: district.state_id,
      cases: district.cases,
      cured: district.cured,
      active: district.active,
      deaths: district.deaths,
    }
    response.send(districtDetails)
  },
)

//API-6
app.delete(
  '/districts/:districtId/',
  authenticationMiddleware,
  async (request, response) => {
    const {districtId} = request.params
    const deleteDistrictQuery = `
        DELETE FROM district
        WHERE district_id = ${districtId};
    `
    await db.run(deleteDistrictQuery)
    response.send('District Removed')
  },
)

//API-7
app.put(
  '/districts/:districtId/',
  authenticationMiddleware,
  async (request, response) => {
    const {districtName, stateId, cases, cured, active, deaths} = request.body
    const updateDistrictQuery = `
        UPDATE district
        SET 
            district_name = '${districtName}',
            state_id = '${stateId}',
            cases = '${cases}',
            cured = '${cured}',
            active = '${active}',
            deaths = '${deaths}';
    `
    await db.run(updateDistrictQuery)
    response.send('District Details Updated')
  },
)

app.get(
  '/states/:stateId/stats/',
  authenticationMiddleware,
  async (request, response) => {
    const {stateId} = request.params
    const getStateStatsQuery = `
    SELECT
      SUM(cases),
      SUM(cured),
      SUM(active),
      SUM(deaths)
    FROM
      district
    WHERE
      state_id=${stateId};`
    const stats = await db.get(getStateStatsQuery)
    response.send({
      totalCases: stats['SUM(cases)'],
      totalCured: stats['SUM(cured)'],
      totalActive: stats['SUM(active)'],
      totalDeaths: stats['SUM(deaths)'],
    })
  },
)

module.exports = app
