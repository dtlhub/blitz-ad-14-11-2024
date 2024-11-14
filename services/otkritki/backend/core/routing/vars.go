package routing

import (
	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
	"otkritki/core/db"
)

const cookieName = "session"
const authKey = "authenticated"
const genderKey = "gender"
const idKey = "id"

const usernameLen = 10
const passwordLen = 10

var database *db.DB
var cookieStore *sessions.CookieStore
var encoder *schema.Encoder
var decoder *schema.Decoder
