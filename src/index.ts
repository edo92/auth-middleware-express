const { refreshTokens, decode, verify } = require('auth-token-registry');

export default (findUser: any, SECRET_1: any, SECRET_2: any) => ({
    auth: async (req: any, res: any, next: any) => {
        // Get headers
        const token = req.headers['x-token'];
        const refreshToken = req.headers['x-refresh-token'];

        // Headers validity
        if (!req.headers) {
            return next();
        }

        // Check for token
        if (!token) {
            return next();
        }

        // Compare token with cookie token
        const cookieToken = req.cookies.token;
        if (!cookieToken || token !== cookieToken) {
            return next();
        }

        try { // Verify token
            const { user } = await verify(token, SECRET_1);
            req.user = user;
        }
        catch (err) { // Reauthenticate with refresh token
            //  Check for refresh token
            if (!refreshToken) {
                return next();
            }

            // Compare refresh token with cookie resfreshtoken
            const cookieRefreshToken = req.cookies['refresh-token'];
            if (!cookieRefreshToken || refreshToken !== cookieRefreshToken) {
                return next();
            }

            try {
                // Decode refresh token
                await decode(refreshToken, SECRET_2);
                // If refresh token is valid reshresh token
                const newTokens = await refreshTokens(refreshToken, findUser, SECRET_1, SECRET_2);

                // If new token is regenerated
                if (newTokens.token && newTokens.refreshToken) {
                    // Setting headers
                    res.set('Access-Control-Expose-Headers', 'x-token, x-refresh-token');
                    res.set('x-token', newTokens.token);
                    res.set('x-refresh-token', newTokens.refreshToken);
                    // Setting cookie
                    res.cookie('token', newTokens.token, { maxAge: 60 * 60 * 24 * 7, httpOnly: true });
                    res.cookie('refresh-token', newTokens.refreshToken, {
                        maxAge: 60 * 60 * 24 * 7,
                        httpOnly: true,
                    });
                    req.user = newTokens.user; // set user to req object
                }
            } catch (err) { return next() }
        }
    }
})