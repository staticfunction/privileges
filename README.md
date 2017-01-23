# Privileges
Routing middleware for Express using bits.

## Getting Started
Privileges references req.user.privileges for its checks. Use any method you want to populate the req.user.privileges.

```
    npm install privileges --save
```

For example:

```
    var guard = privileges.express();

    app.get('/', 
    (req, res, next) => {
        users.findOne({username: req.user.username}, (err, user) => {
            req.user.privileges = user.privileges;
            next();
        })
    }, 
    guard
        .check(2, (req, res, next) => {
            //admin access
        })
    )
```

## Multi-level Access Routing

```
    app.get('/', 
    (req, res, next) => {
        users.findOne({username: req.user.username}, (err, user) => {
            req.user.privileges = user.privileges;
            next();
        })
    }, 
    guard
        .check(2, (req, res, next) => {
            //user access
        })
        .check(4, (req, res, next) => {
            //admin access
        })
```

## Errors Thrown
If there's no req.user the privileges throws 401 Unauthorized. If privileges is undefined or that privileges is not enough it throws a 403 Forbidden.
