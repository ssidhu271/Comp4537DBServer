const { db, queries } = require('../utils/dbHelper');

// Add a new .wav file
async function addWavFile(req, res) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
        const { userId, fileName, filePath } = JSON.parse(body);
        try {
            await db.runQuery(queries.insertWavFile, [userId, fileName, filePath]);
            res.statusCode = 201;
            res.end(JSON.stringify({ message: "WAV file added successfully." }));
        } catch (error) {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: "Error adding WAV file." }));
        }
    });
}

// Get all .wav files for a user
async function getWavFilesByUser(req, res, userId) {
    try {
        const wavFiles = await db.allQuery(queries.getWavFilesByUser, [userId]);
        res.statusCode = 200;
        res.end(JSON.stringify(wavFiles));
    } catch (error) {
        res.statusCode = 500;
        res.end(JSON.stringify({ error: "Error fetching WAV files." }));
    }
}

// Update .wav file name
async function updateWavFileName(req, res, id) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
        const { userId, fileName } = JSON.parse(body);
        try {
            await db.runQuery(queries.updateWavFileName, [fileName, id, userId]);
            res.statusCode = 200;
            res.end(JSON.stringify({ message: "WAV file name updated successfully." }));
        } catch (error) {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: "Error updating WAV file name." }));
        }
    });
}

// Delete .wav file
async function deleteWavFile(req, res, id) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
        const { userId } = JSON.parse(body);
        try {
            await db.runQuery(queries.deleteWavFile, [id, userId]);
            res.statusCode = 200;
            res.end(JSON.stringify({ message: "WAV file deleted successfully." }));
        } catch (error) {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: "Error deleting WAV file." }));
        }
    });
}

module.exports = {
    addWavFile,
    getWavFilesByUser,
    updateWavFileName,
    deleteWavFile
};
