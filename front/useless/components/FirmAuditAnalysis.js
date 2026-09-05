import { useState } from 'react';
import { Button, Typography, Select, MenuItem, CircularProgress, Box } from '@mui/material';
import axios from 'axios';

const FirmAuditAnalysis = () => {
    const [selectedScript, setSelectedScript] = useState('FirmAudit');
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState('');

    const handleScriptChange = (event) => {
        setSelectedScript(event.target.value);
    };

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleSubmit = async () => {
        if (!file) {
            alert('Please upload a file');
            return;
        }

        setLoading(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('script_name', selectedScript);

        try {
            const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            setResult(response.data.output);
        } catch (error) {
            console.error('Error uploading file:', error);
            setResult('An error occurred while processing the file.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <Typography variant="h4">Firmware Analysis</Typography>

            {/* Text above the dropdown list */}
            <Typography variant="subtitle1" style={{ marginTop: '20px', marginBottom: '10px' }}>
                Select Script
            </Typography>

            <div style={{ marginBottom: '20px' }}>
                <Select
                    value={selectedScript}
                    onChange={handleScriptChange}
                    fullWidth
                >
                    <MenuItem value="FirmAudit">FirmAudit.py</MenuItem>
                    <MenuItem value="entropy">entropy.py</MenuItem>
                    <MenuItem value="extractor">extractor.py</MenuItem>
                    <MenuItem value="squashfs_utils">squashfs_utils.py</MenuItem>
                    <MenuItem value="uimage_lookup_tables">uimage_lookup_tables.py</MenuItem>
                </Select>
            </div>

            <div style={{ marginBottom: '20px' }}>
                <input
                    accept=".bin"
                    style={{ display: 'none' }}
                    id="upload-file"
                    type="file"
                    onChange={handleFileChange}
                />
                <label htmlFor="upload-file">
                    <Button
                        variant="contained"
                        component="span"
                        style={{ width: 'auto', maxWidth: '100%' }}
                    >
                        {file ? file.name : 'Upload File'}
                    </Button>
                </label>
            </div>

            <Button
                variant="contained"
                color="primary"
                onClick={handleSubmit}
                disabled={loading}
                style={{ width: 'auto', maxWidth: '100%' }}
            >
                {loading ? <CircularProgress size={24} /> : 'Submit'}
            </Button>

            {result && (
                <Box
                    sx={{
                        marginTop: '20px',
                        padding: '16px',
                        border: '1px solid #ccc',
                        borderRadius: '4px',
                        maxHeight: '400px',
                        overflow: 'auto',
                        whiteSpace: 'pre', // Preserve whitespace and line breaks
                        fontFamily: 'Monaco, monospace' // Monospaced font for terminal-like appearance
                    }}
                >
                    <Typography variant="body1" sx={{ fontFamily: 'Monaco, monospace' }}>
                        {result}
                    </Typography>
                </Box>
            )}
        </div>
    );
};

export default FirmAuditAnalysis;











































/*
import { useState } from 'react';
import { Button, Typography, Select, MenuItem, CircularProgress, Box } from '@mui/material';
import axios from 'axios';

const FirmAuditAnalysis = () => {
    const [selectedScript, setSelectedScript] = useState('FirmAudit');
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState('');

    const handleScriptChange = (event) => {
        setSelectedScript(event.target.value);
    };

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleSubmit = async () => {
        if (!file) {
            alert('Please upload a file');
            return;
        }

        setLoading(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('script_name', selectedScript);

        try {
            const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            setResult(response.data.output);
        } catch (error) {
            console.error('Error uploading file:', error);
            setResult('An error occurred while processing the file.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <Typography variant="h4">Firmware Analysis</Typography>

            {/* Text above the dropdown list */}
            <Typography variant="subtitle1" style={{ marginTop: '20px', marginBottom: '10px' }}>
                Select Script
            </Typography>

            <div style={{ marginBottom: '20px' }}>
                <Select
                    value={selectedScript}
                    onChange={handleScriptChange}
                    fullWidth
                >
                    <MenuItem value="FirmAudit">FirmAudit.py</MenuItem>
                    <MenuItem value="entropy">entropy.py</MenuItem>
                    <MenuItem value="extractor">extractor.py</MenuItem>
                    <MenuItem value="squashfs_utils">squashfs_utils.py</MenuItem>
                    <MenuItem value="uimage_lookup_tables">uimage_lookup_tables.py</MenuItem>
                </Select>
            </div>

            <div style={{ marginBottom: '20px' }}>
                <input
                    accept=".bin"
                    style={{ display: 'none' }}
                    id="upload-file"
                    type="file"
                    onChange={handleFileChange}
                />
                <label htmlFor="upload-file">
                    <Button
                        variant="contained"
                        component="span"
                        style={{ width: 'auto', maxWidth: '100%' }}
                    >
                        {file ? file.name : 'Upload File'}
                    </Button>
                </label>
            </div>

            <Button
                variant="contained"
                color="primary"
                onClick={handleSubmit}
                disabled={loading}
                style={{ width: 'auto', maxWidth: '100%' }}
            >
                {loading ? <CircularProgress size={24} /> : 'Submit'}
            </Button>

            {result && (
                <Box
                    sx={{
                        marginTop: '20px',
                        padding: '16px',
                        border: '1px solid #ccc',
                        borderRadius: '4px',
                        maxHeight: '400px',
                        overflow: 'auto',
                        whiteSpace: 'pre', // Preserve whitespace and line breaks
                        fontFamily: 'Monaco, monospace' // Monospaced font for terminal-like appearance
                    }}
                >
                    <Typography variant="body1" sx={{ fontFamily: 'Monaco, monospace' }}>
                        {result}
                    </Typography>
                </Box>
            )}
        </div>
    );
};

export default FirmAuditAnalysis;
*/




































/*
import { useState } from 'react';
import { Button, Typography, Select, MenuItem, CircularProgress, Box } from '@mui/material';
import axios from 'axios';

const FirmAuditAnalysis = () => {
    const [selectedScript, setSelectedScript] = useState('FirmAudit');
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState('');

    const handleScriptChange = (event) => {
        setSelectedScript(event.target.value);
    };

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleSubmit = async () => {
        if (!file) {
            alert('Please upload a file');
            return;
        }

        setLoading(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('script_name', selectedScript);

        try {
            const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            setResult(response.data.output);
        } catch (error) {
            console.error('Error uploading file:', error);
            setResult('An error occurred while processing the file.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <Typography variant="h4">Firmware Analysis</Typography>
            <div style={{ marginBottom: '20px' }}>
                <Select
                    value={selectedScript}
                    onChange={handleScriptChange}
                    fullWidth
                >
                    <MenuItem value="FirmAudit">FirmAudit.py</MenuItem>
                    <MenuItem value="entropy">entropy.py</MenuItem>
                    <MenuItem value="extractor">extractor.py</MenuItem>
                    <MenuItem value="squashfs_utils">squashfs_utils.py</MenuItem>
                    <MenuItem value="uimage_lookup_tables">uimage_lookup_tables.py</MenuItem>
                </Select>
            </div>
            <div style={{ marginBottom: '20px' }}>
                <input
                    accept=".bin"
                    style={{ display: 'none' }}
                    id="upload-file"
                    type="file"
                    onChange={handleFileChange}
                />
                <label htmlFor="upload-file">
                    <Button variant="contained" component="span">
                        Upload File
                    </Button>
                </label>
            </div>
            <Button
                variant="contained"
                color="primary"
                onClick={handleSubmit}
                disabled={loading}
            >
                {loading ? <CircularProgress size={24} /> : 'Submit'}
            </Button>
            {result && (
                <Box
                    sx={{
                        marginTop: '20px',
                        padding: '16px',
                        border: '1px solid #ccc',
                        borderRadius: '4px',
                        maxHeight: '400px',
                        overflow: 'auto',
                        whiteSpace: 'pre', // Preserve whitespace and line breaks
                        fontFamily: 'Monaco, monospace' // Monospaced font for terminal-like appearance
                    }}
                >
                    <Typography variant="body1" sx={{ fontFamily: 'Monaco, monospace' }}>
                        {result}
                    </Typography>
                </Box>
            )}
        </div>
    );
};

export default FirmAuditAnalysis;

*/










































/*
import { useState } from 'react';
import { Button, Typography, Select, MenuItem, CircularProgress, Box } from '@mui/material';
import axios from 'axios';

const FirmAuditAnalysis = () => {
    const [selectedScript, setSelectedScript] = useState('FirmAudit');
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState('');

    const handleScriptChange = (event) => {
        setSelectedScript(event.target.value);
    };

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleSubmit = async () => {
        if (!file) {
            alert('Please upload a file');
            return;
        }

        setLoading(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('script_name', selectedScript);

        try {
            const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            setResult(response.data.output);
        } catch (error) {
            console.error('Error uploading file:', error);
            setResult('An error occurred while processing the file.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <Typography variant="h4">Firmware Analysis</Typography>
            <div style={{ marginBottom: '20px' }}>
                <Select
                    value={selectedScript}
                    onChange={handleScriptChange}
                    fullWidth
                >
                    <MenuItem value="FirmAudit">FirmAudit.py</MenuItem>
                    <MenuItem value="entropy">entropy.py</MenuItem>
                    <MenuItem value="extractor">extractor.py</MenuItem>
                    <MenuItem value="squashfs_utils">squashfs_utils.py</MenuItem>
                    <MenuItem value="uimage_lookup_tables">uimage_lookup_tables.py</MenuItem>
                </Select>
            </div>
            <div style={{ marginBottom: '20px' }}>
                <input
                    accept=".bin"
                    style={{ display: 'none' }}
                    id="upload-file"
                    type="file"
                    onChange={handleFileChange}
                />
                <label htmlFor="upload-file">
                    <Button variant="contained" component="span">
                        Upload File
                    </Button>
                </label>
            </div>
            <Button
                variant="contained"
                color="primary"
                onClick={handleSubmit}
                disabled={loading}
            >
                {loading ? <CircularProgress size={24} /> : 'Submit'}
            </Button>
            {result && (
                <Box
                    sx={{
                        marginTop: '20px',
                        padding: '16px',
                        border: '1px solid #ccc',
                        borderRadius: '4px',
                        maxHeight: '400px',
                        overflow: 'auto',
                        whiteSpace: 'pre-wrap', // Preserve whitespace and line breaks
                        fontFamily: 'Monaco, monospace' // Monospaced font for terminal-like appearance
                    }}
                >
                    <Typography variant="body1">
                        {result}
                    </Typography>
                </Box>
            )}
        </div>
    );
};

export default FirmAuditAnalysis;
*/






































/*
import { useState } from 'react';
import { Button, Typography, Select, MenuItem, TextField, CircularProgress, Box } from '@mui/material';
import axios from 'axios';

const FirmAuditAnalysis = () => {
    const [selectedScript, setSelectedScript] = useState('FirmAudit');
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState('');

    const handleScriptChange = (event) => {
        setSelectedScript(event.target.value);
    };

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleSubmit = async () => {
        if (!file) {
            alert('Please upload a file');
            return;
        }

        setLoading(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('script_name', selectedScript);

        try {
            const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            setResult(response.data.output);
        } catch (error) {
            console.error('Error uploading file:', error);
            setResult('An error occurred while processing the file.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <Typography variant="h4">Firmware Analysis</Typography>
            <div style={{ marginBottom: '20px' }}>
                <Select
                    value={selectedScript}
                    onChange={handleScriptChange}
                    fullWidth
                >
                    <MenuItem value="FirmAudit">FirmAudit.py</MenuItem>
                    <MenuItem value="entropy">entropy.py</MenuItem>
                    <MenuItem value="extractor">extractor.py</MenuItem>
                    <MenuItem value="squashfs_utils">squashfs_utils.py</MenuItem>
                    <MenuItem value="uimage_lookup_tables">uimage_lookup_tables.py</MenuItem>
                </Select>
            </div>
            <div style={{ marginBottom: '20px' }}>
                <input
                    accept=".bin"
                    style={{ display: 'none' }}
                    id="upload-file"
                    type="file"
                    onChange={handleFileChange}
                />
                <label htmlFor="upload-file">
                    <Button variant="contained" component="span">
                        Upload File
                    </Button>
                </label>
            </div>
            <Button
                variant="contained"
                color="primary"
                onClick={handleSubmit}
                disabled={loading}
            >
                {loading ? <CircularProgress size={24} /> : 'Submit'}
            </Button>
            {result && (
                <Box
                    sx={{
                        marginTop: '20px',
                        padding: '16px',
                        border: '1px solid #ccc',
                        borderRadius: '4px',
                        maxHeight: '400px',
                        overflow: 'auto',
                        whiteSpace: 'pre-wrap' // Preserve whitespace and line breaks
                    }}
                >
                    <Typography variant="body1">
                        {result}
                    </Typography>
                </Box>
            )}
        </div>
    );
};

export default FirmAuditAnalysis;
*/


















































/*
import { useState } from 'react';
import { Button, Typography, Select, MenuItem, TextField, CircularProgress } from '@mui/material';
import axios from 'axios';

const FirmAuditAnalysis = () => {
    const [selectedScript, setSelectedScript] = useState('FirmAudit');
    const [file, setFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState('');

    const handleScriptChange = (event) => {
        setSelectedScript(event.target.value);
    };

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleSubmit = async () => {
        if (!file) {
            alert('Please upload a file');
            return;
        }

        setLoading(true);

        const formData = new FormData();
        formData.append('file', file);
        formData.append('script_name', selectedScript);

        try {
            const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            });

            setResult(response.data.output || 'No output');
        } catch (error) {
            console.error('Error uploading file:', error);
            setResult('An error occurred while processing the file.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ textAlign: 'center' }}>
            <Typography variant="h4">Firmware Analysis</Typography>
            <div style={{ margin: '20px auto', maxWidth: '500px' }}>
                <Select
                    value={selectedScript}
                    onChange={handleScriptChange}
                    fullWidth
                    variant="outlined"
                    style={{ marginBottom: '20px' }}
                >
                    <MenuItem value="FirmAudit">FirmAudit.py</MenuItem>
                    <MenuItem value="entropy">entropy.py</MenuItem>
                    <MenuItem value="extractor">extractor.py</MenuItem>
                    <MenuItem value="squashfs_utils">squashfs_utils.py</MenuItem>
                    <MenuItem value="uimage_lookup_tables">uimage_lookup_tables.py</MenuItem>
                </Select>
                {selectedScript === 'FirmAudit' && (
                    <TextField
                        label="Extra Argument"
                        variant="outlined"
                        fullWidth
                        disabled
                        defaultValue="-info"
                        style={{ marginBottom: '20px' }}
                    />
                )}
                <input
                    type="file"
                    onChange={handleFileChange}
                    style={{ marginBottom: '20px' }}
                />
                <Button
                    variant="contained"
                    color="primary"
                    onClick={handleSubmit}
                    disabled={loading}
                >
                    {loading ? <CircularProgress size={24} /> : 'Run Script'}
                </Button>
                <div style={{ marginTop: '20px' }}>
                    <Typography variant="h6">Result:</Typography>
                    <pre>{result}</pre>
                </div>
            </div>
        </div>
    );
};

export default FirmAuditAnalysis;
*/














































/*
import { useState } from 'react';
import axios from 'axios';
import { Button, Typography } from '@mui/material';
import FolderMenu from './FolderMenu';

const FirmAuditAnalysis = () => {
    const [file, setFile] = useState(null);
    const [output, setOutput] = useState("");

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append("file", file);

        try {
            const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/upload/`, formData, {
                headers: {
                    "Content-Type": "multipart/form-data",
                },
            });
            setOutput(response.data.output);
        } catch (error) {
            console.error('Error uploading file:', error);
        }
    };

    return (
        <div className="container">
            <Typography variant="h4">Firm Audit Analysis</Typography>
            <form onSubmit={handleSubmit} className="form-group">
                <input type="file" onChange={handleFileChange} />
                <Button type="submit" variant="contained" color="primary">Upload</Button>
            </form>
            <div className="output">
                <Typography variant="h6">Output</Typography>
                <pre>{output}</pre>
            </div>
            <div className="files">
                <Typography variant="h6">Extracted Files</Typography>
                <FolderMenu />
            </div>
        </div>
    );
};

export default FirmAuditAnalysis;
*/