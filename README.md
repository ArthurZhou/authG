# authG
Light weight OAuth2 like auth system written in Golang

## Installation

### Create a database

authG use `sqlite3` to build a database. So install it first.

Create file `accounts.sqlite` under `db` folder.
Use the following SQL command to create a table

```sqlite
CREATE TABLE Account
(
    ID       INTEGER,
    Username TEXT,
    Hash     TEXT,
    uuid     TEXT,
    PRIMARY KEY (ID)
)
```

### Connect with your service

`service/main.go` is a sample service. Have a look at it.

If you want to write it yourself, see the API documents below.

### API

#### Add auth

URL: `/add_auth`

Method: `POST`

Required header(s): `Content-Type: application/x-www-form-urlencoded`

Request body: (Form)

```json
{
  "redirect": "<authG will redirect users to this url after login>"
}
```

**Notice: Normally, you need to add a parameter `token={{token}}` in the redirect url.
authG will replace `{{token}}` with an ID when redirecting users.
And you can query the users' login status with this ID.**

Response body: (JSON text)

```json
{
  "status": true,
  "reason": "<more about the current status of your request>"
}
```

#### Query auth

URL: `/query_auth`

Method: `POST`

Required header(s): `Content-Type: application/x-www-form-urlencoded`

Request body: (Form)

```json
{
  "token": "<an ID provided in the user's url parameters>"
}
```

Response body: (JSON text)

```json
{
  "status": true,
  "reason": "<more about the current status of your request>"
}
```