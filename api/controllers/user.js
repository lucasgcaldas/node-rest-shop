const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require("../models/user");

exports.user_signup = (req, res, next) => {
    User.find({email: req.body.email})
        .exec()
        .then(user => {
            if(user.length >= 1){
                return res.status(409).json({
                    messsage: 'Mail existe'
                });
            } else {
                bcrypt.hash(req.body.password, 10, (err, hash) => {
                    if (err) {
                        return res.status(500).json({
                            error: err
                        });
                    } else {
                        const user = new User({
                            _id: new mongoose.Types.ObjectId(),
                            email: req.body.email,
                            password: hash
                        });
                        user
                            .save()
                            .then(result => {
                                console.log(result);
                                res.status(201).json({
                                    messsage: 'User created'
                                });
                            })
                            .catch(err => {
                                console.log(err);
                                res.status(500).json({
                                     err: err
                                });
                            });
                    }
                    });
            }    
        })    
}

exports.user_login = (req, res, next) => {
    User.find({ email: req.body.email })
        .exec()
        .then(user => {
            if(user.length < 1) {
                return res.status(401).json({
                    messsage: 'Auth failed'
                });
            }
            bcrypt.compare(req.body.password, user[0].password, (err, result) => {
                if (err) {
                    return res.status(401).json({
                        messsage: 'Auth failed'
                    });
                }
                if (result) {
                    const token = jwt.sign({
                        email: user[0].email,
                        userId: user[0]._id
                        }, 
                        process.env.JWT_KEY,
                        {
                            expiresIn: "1h"
                        }
                    );
                    return res.status(200).json({
                        messsage: 'Auth successful',
                        token: token
                    });
                }
                return res.status(401).json({
                    messsage: 'Auth failed'
                });            
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ err: err });
        });
}

exports.user_delete = (req, res, next) => {
    User.remove({_id: req.params.userId})
        .exec()
        .then(result => {
            res.status(200).json({
                messsage: 'User deleted'
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ err: err });
        });
}