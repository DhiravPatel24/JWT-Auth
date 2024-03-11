const jwt = require('jsonwebtoken');
const User = require('../models/User.js');

const requireAuth = (req, res, next) => {
    const token = req.cookies.jwt;

    if (token) {
        jwt.verify(token, 'secret', async (err, decodedToken) => {
            if (err || !isValidPayload(decodedToken)) {
                res.clearCookie('jwt');
                return res.redirect('/login');
            }

            try {

                const user = await User.findById(decodedToken.id);
                if (!user) {

                    res.clearCookie('jwt');
                    return res.redirect('/login');
                }
                res.locals.user = user;
                next();
            } catch (error) {
                console.error(error);
                res.clearCookie('jwt');
                res.redirect('/login');
            }
        });
    } else {

        res.redirect('/login');
    }
};

const isValidPayload = async (decodedToken) => {
    if (!decodedToken || typeof decodedToken !== 'object') {
        return false;
    }
    
    try {

        const { email, password } = decodedToken;
        
        const user = await User.findOne({ email });
        
        if (!user || user.password !== password) {
            return false;
        }
       
        if (user.email !== email) {
            return false;
        }
        return true;
    } catch (error) {
        console.error('Error validating payload:', error);
        return false;
    }
};

const checkUser = (req, res, next) => {
    const token = req.cookies.jwt;

    if (token) {
        jwt.verify(token, 'secret', async (err, decodedToken) => {
            if (err) {
                console.error('Error verifying token:', err);
               
                res.clearCookie('jwt');
                return res.redirect('/login');
            } else {
                try {
                    if (!decodedToken || !decodedToken.email || !decodedToken.password) {
                        console.error('Invalid token payload');
                        throw new Error('Invalid token payload');
                    }

                    const user = await User.findOne({ email: decodedToken.email });
                    if (!user) {
                        console.error('User not found');
                        res.clearCookie('jwt');
                        return res.redirect('/login');
                    } else {
                        if (user.password !== decodedToken.password) {
                            console.error('Password mismatch');
                            res.clearCookie('jwt');
                            return res.redirect('/login');
                        }
                        res.locals.user = user;
                        return next();
                    }
                } catch (error) {
                    console.error('Error in checkUser middleware:', error);
                    res.clearCookie('jwt');
                    return res.redirect('/login');
                }
            }
        });
    } else {
        
        res.locals.user = null;
        return next();
    }
};

module.exports = {
    requireAuth,
    checkUser
}



