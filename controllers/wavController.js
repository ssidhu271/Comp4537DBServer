// ChatGPT helped with the creation of this file

const { db, runQuery, getQuery, allQuery, queries } = require('../utils/dbHelper');
const handleCors = require('../middlewares/handleCors');
const fs = require('fs');
const path = require('path');

// Add a new .wav file
const addWavFile = async (req, res) => {
    if (handleCors(req, res)) return;

    try {
        let body = "";
        req.on("data", chunk => body += chunk);
        req.on("end", async () => {
            const { fileName, fileBlob } = JSON.parse(body);
            const userId = req.user.id;

            // Decode base64 data to a Buffer
            const buffer = Buffer.from(fileBlob, "base64");
            const filePath = path.join(__dirname, "../uploads", `${fileName}.wav`);

            // Save the file in the uploads directory
            fs.writeFileSync(filePath, buffer);

            // Provide a URL that the frontend can use for download
            const relativePath = `/uploads/${fileName}.wav`;
            await runQuery("INSERT INTO wav_files (user_id, file_name, file_path) VALUES (?, ?, ?)", [userId, fileName, relativePath]);

            res.statusCode = 201;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ message: "WAV file added successfully.", filePath: relativePath }));
        });
    } catch (error) {
        console.error("Error in addWavFile:", error);
        res.statusCode = 500;
        res.end(JSON.stringify({ error: "Error adding WAV file." }));
    }
};

const getWavFilesByUser = async (req, res) => {
    if (handleCors(req, res)) return;

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
        res.end(JSON.stringify({ error: "Error fetching WAV files." }));
    }
};



// Update .wav file name
const updateWavFileName = async (req, res) => {
    if (handleCors(req, res)) return;

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
            res.end(JSON.stringify({ message: "WAV file name updated successfully." }));
        });
    } catch (error) {
        console.error("Error in updateWavFileName:", error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: "Error updating WAV file name." }));
    }
};

// Delete .wav file
const deleteWavFile = async (req, res) => {
    if (handleCors(req, res)) return;

    try {
        const userId = req.user.id;
        const id = req.params.id;

        await runQuery('DELETE FROM wav_files WHERE id = ? AND user_id = ?', [id, userId]);
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ message: "WAV file deleted successfully." }));
    } catch (error) {
        console.error("Error in deleteWavFile:", error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: "Error deleting WAV file." }));
    }
};

module.exports = {
    addWavFile,
    getWavFilesByUser,
    updateWavFileName,
    deleteWavFile
};
