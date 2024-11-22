// ChatGPT helped with the creation of this file

const { db, runQuery, getQuery, allQuery, queries } = require('../utils/dbHelper');
const handleCors = require('../middlewares/handleCors');
const fs = require('fs');
const path = require('path');
const { incrementApiUsage } = require('../controllers/apiController');
const MESSAGE = require('../lang/messages/en/user');

// Add a new .wav file
const addWavFile = async (req, res) => {
    if (handleCors(req, res)) return;

    const userId = req.user.id;
    incrementApiUsage(MESSAGE.api.addWavFile, 'POST', userId);

    try {
        let body = "";
        req.on("data", chunk => body += chunk);
        req.on("end", async () => {
            const { fileName, fileBlob } = JSON.parse(body);
            const userId = req.user.id;

            // Ensure the filename ends with .wav
            const sanitizedFileName = fileName.endsWith('.wav') ? fileName : `${fileName}.wav`;
            const uploadsDir = path.join(__dirname, "../uploads");
            const filePath = path.join(uploadsDir, sanitizedFileName);

            // Check if the uploads directory exists, if not, create it
            if (!fs.existsSync(uploadsDir)) {
                fs.mkdirSync(uploadsDir);
            }

            // Decode base64 data to a Buffer
            const buffer = Buffer.from(fileBlob, "base64");

            // Save the file in the uploads directory
            fs.writeFileSync(filePath, buffer);

            // Provide a URL that the frontend can use for download
            const relativePath = `/uploads/${sanitizedFileName}`;
            await runQuery("INSERT INTO wav_files (user_id, file_name, file_path) VALUES (?, ?, ?)", [userId, sanitizedFileName, relativePath]);

            res.statusCode = 201;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ message: MESSAGE.messages.wavFileAddedSuccessfully, filePath: relativePath }));
        });
    } catch (error) {
        console.error("Error in addWavFile:", error);
        res.statusCode = 500;
        res.end(JSON.stringify({ error: MESSAGE.errors.errorAddingWavFile }));
    }
};

const getWavFilesByUser = async (req, res) => {
    if (handleCors(req, res)) return;

    const userId = req.user.id;
    incrementApiUsage(MESSAGE.api.getWavFilesByUser, 'GET', userId);

    try {
        const userId = req.user.id;
        const wavFiles = await allQuery(queries.getWavFilesByUser, [userId]); // Use allQuery here
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(wavFiles));
    } catch (error) {
        console.error("Error in getWavFilesByUser:", error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: MESSAGE.errors.errorFetchingWavFiles }));
    }
};



// Update .wav file name
const updateWavFileName = async (req, res) => {
    if (handleCors(req, res)) return;

    const userId = req.user.id;
    incrementApiUsage(MESSAGE.api.updateWavFileName, 'PUT', userId);

    try {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            const { fileName } = JSON.parse(body);
            const userId = req.user.id;
            const id = req.params.id;

            await runQuery('UPDATE wav_files SET file_name = ? WHERE id = ? AND user_id = ?', [fileName, id, userId]);
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ message: MESSAGE.messages.wavFileNameUpdatedSuccessfully }));
        });
    } catch (error) {
        console.error("Error in updateWavFileName:", error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: MESSAGE.errors.errorUpdatingWavFileName }));
    }
};

// Delete .wav file
const deleteWavFile = async (req, res) => {
    if (handleCors(req, res)) return;

    const userId = req.user.id;
    incrementApiUsage(MESSAGE.api.deleteWavFile, 'DELETE', userId);

    try {
        const userId = req.user.id;
        const id = req.params.id;

        await runQuery('DELETE FROM wav_files WHERE id = ? AND user_id = ?', [id, userId]);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ message: MESSAGE.messages.wavFileDeletedSuccessfully }));
    } catch (error) {
        console.error("Error in deleteWavFile:", error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: MESSAGE.errors.errorDeletingWavFile }));
    }
};

module.exports = {
    addWavFile,
    getWavFilesByUser,
    updateWavFileName,
    deleteWavFile
};
