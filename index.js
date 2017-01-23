exports.express = () => {

    var Express = function() {
        var handler = function (req, res, next) {

            if(!req.user)
                return next({status: 401, code: "unauthorized", message: "you don't have authorization to view this resource"});

            var noPrivilegeError = {status: 403, code: "forbidden", message: "you don't have privilege to view this resource"};
            
            if(req.user.privileges === undefined)
                return next(noPrivilegeError);

            handler.callbacks.forEach((callback) => {
                if(callback.mask == (callback.mask & req.user.privileges))
                    return callback(req, res, next);
            })

            next(noPrivilegeError);
        }

        handler.callbacks = [];

        handler.check = (mask, callback) => {

            var clone = Express();
            
            clone.callbacks = handler.callbacks.slice();

            callback.mask = mask;
            
            clone.callbacks.push(callback);

            return clone;
        }

        return handler;
    }

    return Express();
}