# Bouquets

Сервис букетиков. В сервисе можно было создавать букеты с различным набором цветочков, отправлять (дарить) свои букеты другим пользователям. Так же был функционал покупки подписки "в рассрочку", при помощи которой можно было видеть предпочтения других пользователей и на основе этого отправлять им букетики

Стек:

- Python
- Flask
- SQLite

## Уязвимости сервиса

### 1. SQL-Injection

В функции фильтрации букетов содержится sql - инъекция

```python
@staticmethod
    def filter_bouquets(filter, value, username):
        query = f"SELECT id, name, owner, cost, description, sent_to FROM bouquet WHERE owner = ? AND {filter} = ?"
        res = connection_manager(query, username, value)
        if not res:
            return
        return [Bouquet.get_bouquet(row) for row in res]
```

Поле field - это контроллируемое пользователем значение, поэтому мы можем "пропихнуть кавычку" и написать что то вроде этого

```
GET /bouquet/filter?field=1=1%20UNION%20SELECT%20id,%20name,%20owner,%20cost,%20description,%20sent_to%20from%20bouquet%20where%20name%20like%20'%%'%20or%201&value=1
```

### 2. IDOR

Есть фича - посмотреть какие букеты тебе прислали. Ручка /bouquet/given принимает в качестве GET-параметров поля: user_from и user_to, при этом отсутствует проверка на то, что user_to - это текущий user.

```python
@bouquet.route("/bouquet/given", methods=["GET"])
@login_required
def get_given_bouquets():
    user = current_user
    if not user:
        return redirect("/login")
    params = request.args
    user_from = params.get("user_from", "")
    user_to = params.get("user_to")
    if not user_to:
        user_to = user.username
    bouquets = Bouquet.get_given_bouquets(user_from, user_to)
    return render_template("bouquets.html", bouquets=bouquets)
```

Если user_to не указан, то выставляется текущий user. Мы же выставим `user_to=default`, потому что при создании букета, до того, как мы его кому то отправили в поле sent_to выставляется default по умолчанию.
Таким образом, можно отправить запрос вида: `/bouquet/given?user_from={USERNAME_FROM_ATTACK_DATA}&user_to=default` и получить все неотправленные букеты пользователя

### 3. Ошибка в логике

Как говорилось ранее в сервисе есть функционал "покупки" подписки, а точнее, функционал аппрува вам покупки подписки так сказать в рассрочку.

```python
def can_pay(user, subscribe_cost, parts):
    if not parts:
        return False
    if parts > MAX_PERIOD or parts==0:
        return False
    current_balance = user.current_balance
    minimal_amount = subscribe_cost / MAX_PERIOD * randint(1, 10)
    if minimal_amount > current_balance / parts:
        return False
    return True
```

Функция `can_pay` проверяет что вы сможете выплатить стоимость всей подписки в будущем, при вашем текущем балансе (он составляет 100 бачей и другим быть не может). В этой функции есть сразу два способа обхода: (1) NaN и (2) Дроби

1. `periods` - user-controllable datа. Которая далее кастуется до `float` -> `periods = float(request.form.get("periods", ""))` Как известно, `float('nan') = nan` и если делать математические операции с `nan` то в итоге получится тоже `nan`. Поэтому, здесь -> `if minimal_amount > current_balance / parts` условие не выполнится, потому что возникает условие неупорядоченности ( справа стоит NaN), а следовательно в результате выполнения всей функции вернется `True`

2. Это пропихнуть дробь например: `parts = 0.0001`, таким образом, при делении текущего баланса на маленькое число - в результате получится значение, сильно большее, чем `minimal_amount` и мы так же обойдем все проверки.
