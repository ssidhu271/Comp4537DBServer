const fs = require('fs');
const path = require('path');

const swaggerUiPath = path.join(__dirname, "../swagger-ui-dist");

function serveSwaggerJSON(req, res) {
    const filePath = path.join(__dirname, "../swagger.json");
    fs.readFile(filePath, "utf8", (err, data) => {
        if (err) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Swagger JSON not found" }));
        } else {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(data);
        }
    });
}

function serveSwaggerUI(req, res) {
    let filePath;

    if (req.url === "/doc" || req.url === "/doc/") {
        filePath = path.join(swaggerUiPath, "index.html");
    } else {
        const assetPath = req.url.replace("/doc", "");
        filePath = path.join(swaggerUiPath, assetPath);
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            console.error(`Error serving file: ${filePath}`, err);
            res.writeHead(404, { "Content-Type": "text/html" });
            res.end("404 Not Found");
            return;
        }

        const ext = path.extname(filePath);
        const contentType = {
            ".html": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".png": "image/png",
            ".svg": "image/svg+xml",
            ".json": "application/json",
            ".ico": "image/x-icon",
        }[ext] || "text/plain";

        res.writeHead(200, { "Content-Type": contentType });
        res.end(data);
    });
}

module.exports = { serveSwaggerJSON, serveSwaggerUI };
