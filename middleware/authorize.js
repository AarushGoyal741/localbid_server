export const authorize = (...allowedTypes) => {
    return (req, res, next) => {

        if (!req.user) {
            return res.status(401).json({
                message: "Not authenticated"
            });
        }

        if (!allowedTypes.includes(req.user.account_type)) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        next();
    };
};