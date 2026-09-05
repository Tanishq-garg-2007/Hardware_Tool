import React, { useState, useEffect } from 'react';
import axios from 'axios';

const FolderMenu = () => {
    const [files, setFiles] = useState([]);
    const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

    useEffect(() => {
        const fetchFiles = async () => {
            try {
                const response = await axios.get(`${apiBase}/list-files/`);
                if (Array.isArray(response.data)) {
                    setFiles(response.data);
                }
            } catch (error) {
                console.error("Error fetching files:", error);
            }
        };
        fetchFiles();
    }, [apiBase]);

    return (
        <div style={{ padding: '16px' }}>
            {files.length === 0 ? (
                <p>No firmware files found in extracted_files.</p>
            ) : (
                <ul>
                    {files.map((file, index) => (
                        <li key={index} style={{ marginBottom: '8px' }}>
                            <a href={`${apiBase}/download_firm/${file}`} target="_blank" rel="noopener noreferrer">
                                {file}
                            </a>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

export default FolderMenu;













/*import { useState, useEffect } from 'react';
import axios from 'axios';

const FolderMenu = () => {
    const [files, setFiles] = useState([]);

    useEffect(() => {
        const fetchFiles = async () => {
            try {
                const response = await axios.get(`${process.env.NEXT_PUBLIC_API_URL}/list-files/`);
                setFiles(response.data);
            } catch (error) {
                console.error("Error fetching files:", error);
            }
        };
        fetchFiles();
    }, []);

    return (
        <div>
            <ul>
                {files.map((file, index) => (
                    <li key={index}>
                        <a href={`${process.env.NEXT_PUBLIC_API_URL}/files/${file}`} target="_blank" rel="noopener noreferrer">
                            {file}
                        </a>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default FolderMenu;
*/





















/*import { useState, useEffect } from 'react';
import axios from 'axios';

const FolderMenu = () => {
    const [files, setFiles] = useState([]);

    useEffect(() => {
        const fetchFiles = async () => {
            try {
                const response = await axios.get(`${process.env.NEXT_PUBLIC_API_URL}/list-files/`);
                setFiles(response.data);
            } catch (error) {
                console.error("Error fetching files:", error);
            }
        };
        fetchFiles();
    }, []);

    return (
        <div>
            <h2>Extracted Files</h2>
            <ul>
                {files.map((file, index) => (
                    <li key={index}>
                        <a href={`${process.env.NEXT_PUBLIC_API_URL}/files/${file}`} target="_blank" rel="noopener noreferrer">
                            {file}
                        </a>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default FolderMenu;
*/









/*// components/FolderMenu.js
import { useState, useEffect } from 'react';
import axios from 'axios';

const FolderMenu = () => {
    const [files, setFiles] = useState([]);

    useEffect(() => {
        const fetchFiles = async () => {
            const response = await axios.get(`${process.env.NEXT_PUBLIC_API_URL}/files`);
            setFiles(response.data);
        };
        fetchFiles();
    }, []);

    return (
        <div>
            <h2>Extracted Files</h2>
            <ul>
                {files.map((file, index) => (
                    <li key={index}>
                        <a href={`${process.env.NEXT_PUBLIC_API_URL}/files/${file}`} target="_blank" rel="noopener noreferrer">
                            {file}
                        </a>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default FolderMenu;
*/
