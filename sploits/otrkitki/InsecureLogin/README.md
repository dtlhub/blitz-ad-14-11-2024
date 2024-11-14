## Описание уязвимости

В исходном коде функции, `LoginPost` отвечающей за аутентификацию пользователя поиск осуществлялся при помощь метода `GetUserByName` без проверки равенства пароля. Таким обарзом можно было зайти от имени любого пользователя и посмотреть его открытки.
```go
if user, err := database.GetUserByName(LoginRequest.Username); err == nil {
		authUser(w, request, user)
	} else {
		abort(w, err.Error())
	}
```

## Эксплуатация

Прямолинейно

## Методы исправления

Проверять равеноство паролей указанного и пользователя.

```go
if user, err := database.GetUserByName(LoginRequest.Username); err != nil {
        abort(w, err.Error())
}
if user.Password == LoginRequest.Password {
    authUser(w, request, user)
} else {
	abort(w, err.Error())
}
```
