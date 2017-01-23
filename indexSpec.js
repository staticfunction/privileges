var privileges = require("./index"),
    chai = require('chai'),
    chaiHttp = require('chai-http'),
    express = require('express');

var expect = chai.expect;
chai.use(chaiHttp);

describe("Privileges", () => {
    describe("Express", () => {
        
        it("throws an unauthorized when there's no req.user", done => {
            
            var guard = privileges.express();

            var app = express();
            app.get('/', guard.check(1, (req, res, next) => {
                res.sendStatus(200);
            }));

            var agent = chai.request.agent(app);

            agent
                .get('/')
                .end((err, res) => {
                    expect(res).to.have.status(401);
                    done();
                })
        })

        it("throws 403 forbidden if there's a user but privilege is undefined", done => {
            var guard = privileges.express();

            var app = express();
            app.get('/', 
                (req, res, next) => {
                   req.user = {}; 
                   next();
                }, guard.check(1, (req, res, next) => {
                res.sendStatus(200);
            }));

            var agent = chai.request.agent(app);

            agent
                .get('/')
                .end((err, res) => {
                    expect(res).to.have.status(403);
                    done();
                })
        })

        it("throws 403 forbidden if privilege is not enough", done => {
            var guard = privileges.express();

            var app = express();
            app.get('/', 
                (req, res, next) => {
                   req.user = {privileges: 1}; 
                   next();
                }, guard.check(2, (req, res, next) => {
                res.sendStatus(200);
            }));

            var agent = chai.request.agent(app);

            agent
                .get('/')
                .end((err, res) => {
                    expect(res).to.have.status(403);
                    done();
                })
        })

        it("proceeds to callback when successful", done => {
            var guard = privileges.express();

            var app = express();
            app.get('/', 
                (req, res, next) => {
                   req.user = {privileges: 7}; 
                   next();
                }, guard.check(2, (req, res, next) => {
                res.sendStatus(200);
            }));

            var agent = chai.request.agent(app);

            agent
                .get('/')
                .end((err, res) => {
                    expect(res).to.have.status(200);
                    done();
                })
        })

        it("proceeds to other callbacks when previous flag is not met", done => {
            var guard = privileges.express();

            var app = express();
            app.get('/', 
                (req, res, next) => {
                   req.user = {privileges: 1}; 
                   next();
                }, guard
                    .check(2, (req, res, next) => {
                        res.sendStatus(200);
                    })
                    .check(1, (req, res, next) => {
                    res.sendStatus(204);
                })
            );

            var agent = chai.request.agent(app);

            agent
                .get('/')
                .end((err, res) => {
                    expect(res).to.have.status(204);
                    done();
                })
        })

        it("stops inheriting callbacks if chain is break", done => {
            var guard = privileges.express();

            var app = express();
            app.get('/', 
                (req, res, next) => {
                   req.user = {privileges: 1}; 
                   next();
                }, guard
                    .check(2, (req, res, next) => {
                        res.sendStatus(200);
                    })
                ,
                guard.check(1, (req, res, next) => {
                    res.sendStatus(204);
                })
            );

            var agent = chai.request.agent(app);

            agent
                .get('/')
                .end((err, res) => {
                    expect(res).to.have.status(403);
                    done();
                })
        })
    })
})