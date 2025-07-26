const fs = require('fs');
const path = require('path');
const axios = require('axios');
const chokidar = require('chokidar');
const FormData = require('form-data'); // ✅ correct package

const watchDir = path.join(__dirname, 'watched-logs');

console.log('📂 Watching folder for new log files:', watchDir);

const watcher = chokidar.watch(watchDir, {
  persistent: true,
  ignoreInitial: true
});

watcher.on('add', async (filePath) => {
  const filename = path.basename(filePath);
  console.log('🆕 New file detected:', filename);

  try {
    const formData = new FormData();
    formData.append('logfile', fs.createReadStream(filePath));

    const response = await axios.post('http://localhost:5000/upload-log', formData, {
      headers: formData.getHeaders()
    });

    console.log('✅ Uploaded:', filename);
    console.log('📊 Response:', response.data.message);

    // Optionally move or delete processed file
    // fs.renameSync(filePath, path.join(__dirname, 'processed', filename));
  } catch (error) {
    console.error('❌ Failed to upload file:', error.message);
  }
});
