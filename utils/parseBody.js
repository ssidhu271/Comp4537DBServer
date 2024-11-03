// utils/parseBody.js
const parseBody = (req) => new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => (body += chunk.toString()));
    req.on('end', () => {
        try {
            resolve(JSON.parse(body));
        } catch (error) {
            reject(error);
        }
    });
    req.on('error', reject);
});

module.exports = parseBody;
