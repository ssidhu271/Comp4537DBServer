//ChatGPT helped with the creation of this file

const handleCors = (req, res) => {
    const allowedOrigin = 'https://happy-island-03f35251e.5.azurestaticapps.net';
    // const allowedOrigin = 'http://localhost:3000';
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        res.end();
        return true;
    }
    return false;
};

module.exports = handleCors;