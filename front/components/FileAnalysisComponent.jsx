import React, { useState, useRef } from 'react';
import axios from 'axios';
import {
  Box,
  Button,
  TextField,
  Typography,
  Paper,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  Divider,
  Alert,
  Chip,
  IconButton,
  Tooltip,
  Grid,
  Avatar
} from '@mui/material';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import SearchIcon from '@mui/icons-material/Search';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import ReplayIcon from '@mui/icons-material/Replay';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import SendIcon from '@mui/icons-material/Send';

const FileAnalysisComponent = () => {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);
  const chatInputRef = useRef(null);
  const chatCardRef = useRef(null);

  // Indexing lifecycle status: 'idle' | 'indexing' | 'success' | 'error'
  const [indexingStatus, setIndexingStatus] = useState('idle');
  const [indexedCount, setIndexedCount] = useState(0);

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searching, setSearching] = useState(false);

  // Chat state
  const [chatQuery, setChatQuery] = useState('');
  const [chatResponse, setChatResponse] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Status & Notification
  const [alertInfo, setAlertInfo] = useState(null); // { type: 'success' | 'error' | 'info', message: string }

  const handleFileChange = (e) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      setSelectedFiles((prev) => [...prev, ...files]);
      setIndexingStatus('idle');
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files) {
      const files = Array.from(e.dataTransfer.files);
      setSelectedFiles((prev) => [...prev, ...files]);
      setIndexingStatus('idle');
    }
  };

  const removeFile = (index) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
    if (selectedFiles.length <= 1) {
      setIndexingStatus('idle');
    }
  };

  const handleUploadAndMerge = async () => {
    if (selectedFiles.length === 0) {
      setAlertInfo({ type: 'warning', message: 'Please select one or more log files first.' });
      return;
    }

    setUploading(true);
    setIndexingStatus('indexing');
    setAlertInfo(null);
    const formData = new FormData();
    selectedFiles.forEach((file) => {
      formData.append('files', file);
    });

    try {
      const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/process-files/`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      const fileCount = selectedFiles.length;
      setIndexedCount(fileCount);
      setIndexingStatus('success');
      setAlertInfo({
        type: 'success',
        message: response.data.message || `Done indexing ${fileCount} file(s) successfully! You can now start chatting below.`
      });

      // Smoothly focus chat input after indexing finishes
      setTimeout(() => {
        chatInputRef.current?.focus();
      }, 400);
    } catch (error) {
      const msg = error.response?.data?.detail || error.response?.data?.error || error.message || 'Error indexing files.';
      setIndexingStatus('error');
      setAlertInfo({ type: 'error', message: `Upload & Indexing Failed: ${msg}` });
    } finally {
      setUploading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    setSearching(true);
    setAlertInfo(null);

    try {
      const response = await axios.get(`${process.env.NEXT_PUBLIC_API_URL}/search-files/`, {
        params: { query: searchQuery }
      });
      setSearchResults(response.data.results || []);
      if (!response.data.results || response.data.results.length === 0) {
        setAlertInfo({ type: 'info', message: `No matches found for "${searchQuery}".` });
      }
    } catch (error) {
      setAlertInfo({ type: 'error', message: 'Search failed. Make sure you indexed the log files first.' });
    } finally {
      setSearching(false);
    }
  };

  const handleChatRequest = async () => {
    if (!chatQuery.trim()) return;
    setChatLoading(true);
    setAlertInfo(null);

    try {
      const response = await axios.post(`${process.env.NEXT_PUBLIC_API_URL}/chat-with-file/`, {
        query: chatQuery
      });
      setChatResponse(response.data.answer || 'No response generated.');
    } catch (error) {
      const msg = error.response?.data?.detail || error.response?.data?.error || error.message || 'AI Chat failed.';
      setAlertInfo({
        type: 'error',
        message: `AI Chat failed: ${msg}. Please verify that Ollama or backend LLM service is running.`
      });
    } finally {
      setChatLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const highlightMatch = (text, query) => {
    if (!query || !text) return text;
    try {
      const parts = text.split(new RegExp(`(${query.replace(/[-/\\^$*+?.()|[\\]{}]/g, '\\\\$&')})`, 'gi'));
      return parts.map((part, i) =>
        part.toLowerCase() === query.toLowerCase() ? (
          <Box
            component="mark"
            key={i}
            sx={{
              bgcolor: '#FEF08A',
              color: '#854D0E',
              px: 0.4,
              py: 0.1,
              borderRadius: '3px',
              fontWeight: 700,
            }}
          >
            {part}
          </Box>
        ) : (
          part
        )
      );
    } catch (e) {
      return text;
    }
  };

  const quickPrompts = [
    'Summarize system boot sequence',
    'List all authentication failures',
    'Check for segmentation faults',
    'Detect hardcoded IP or ports'
  ];

  return (
    <Box sx={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header Banner */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 1 }}>
        <Box>
          <Typography variant="h3" sx={{ fontWeight: 700, color: 'text.primary', letterSpacing: '-0.5px' }}>
            File & Log Analysis
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            Index multi-part logs, run fast regex keyword queries, and interrogate system artifacts with local AI.
          </Typography>
        </Box>

        {/* Dynamic Status Badge in Header */}
        {indexingStatus === 'success' && (
          <Chip
            icon={<CheckCircleIcon sx={{ color: '#10B981 !important' }} />}
            label="✓ Done indexing successfully — Start chatting!"
            sx={{
              borderRadius: '10px',
              fontWeight: 700,
              bgcolor: '#ECFDF5',
              color: '#047857',
              border: '1px solid #A7F3D0',
              px: 0.5
            }}
          />
        )}
        {indexingStatus === 'indexing' && (
          <Chip
            icon={<CircularProgress size={15} color="inherit" />}
            label="Vectorizing & Indexing Files in ChromaDB..."
            color="primary"
            variant="outlined"
            sx={{ borderRadius: '10px', fontWeight: 600, px: 0.5 }}
          />
        )}
        {indexingStatus === 'error' && (
          <Chip
            icon={<ErrorOutlineIcon sx={{ color: '#EF4444 !important' }} />}
            label="Indexing Error — Please Retry"
            sx={{
              borderRadius: '10px',
              fontWeight: 700,
              bgcolor: '#FEF2F2',
              color: '#B91C1C',
              border: '1px solid #FECACA',
              px: 0.5
            }}
          />
        )}
        {indexingStatus === 'idle' && (
          <Chip
            icon={<AutoAwesomeIcon sx={{ fontSize: '16px !important' }} />}
            label="Neural AI & Regex Search"
            color="primary"
            variant="outlined"
            sx={{ borderRadius: '10px', fontWeight: 600 }}
          />
        )}
      </Box>

      {/* Prominent Success Banner: Done indexing successfully */}
      {indexingStatus === 'success' && (
        <Paper
          elevation={0}
          sx={{
            p: 2.5,
            borderRadius: '16px',
            bgcolor: '#F0FDF4',
            border: '1.5px solid #86EFAC',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 2,
            boxShadow: '0 4px 12px rgba(16, 185, 129, 0.08)'
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Avatar sx={{ bgcolor: '#16A34A', width: 44, height: 44, boxShadow: '0 2px 8px rgba(22, 163, 74, 0.3)' }}>
              <CheckCircleIcon sx={{ color: 'white', fontSize: 26 }} />
            </Avatar>
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#14532D' }}>
                Done indexing successfully! Start chatting below.
              </Typography>
              <Typography variant="body2" sx={{ color: '#166534' }}>
                {indexedCount > 0 ? `${indexedCount} log file(s)` : 'All selected files'} successfully vectorized into ChromaDB. Semantic context is active.
              </Typography>
            </Box>
          </Box>
          <Button
            variant="contained"
            endIcon={<ArrowDownwardIcon />}
            onClick={() => {
              chatCardRef.current?.scrollIntoView({ behavior: 'smooth' });
              chatInputRef.current?.focus();
            }}
            sx={{
              borderRadius: '10px',
              fontWeight: 700,
              textTransform: 'none',
              bgcolor: '#16A34A',
              px: 2.5,
              py: 1,
              boxShadow: '0 2px 8px rgba(22, 163, 74, 0.25)',
              '&:hover': { bgcolor: '#15803D' }
            }}
          >
            Start Chatting Now
          </Button>
        </Paper>
      )}

      {/* Prominent Error Banner with Direct Retry Button */}
      {indexingStatus === 'error' && (
        <Paper
          elevation={0}
          sx={{
            p: 2.5,
            borderRadius: '16px',
            bgcolor: '#FEF2F2',
            border: '1.5px solid #FCA5A5',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 2,
            boxShadow: '0 4px 12px rgba(239, 68, 68, 0.08)'
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Avatar sx={{ bgcolor: '#EF4444', width: 44, height: 44 }}>
              <ErrorOutlineIcon sx={{ color: 'white', fontSize: 26 }} />
            </Avatar>
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#7F1D1D' }}>
                Indexing Failed
              </Typography>
              <Typography variant="body2" sx={{ color: '#991B1B' }}>
                {alertInfo?.message || 'Failed to process files. Please verify backend service and retry.'}
              </Typography>
            </Box>
          </Box>
          <Button
            variant="contained"
            color="error"
            startIcon={<ReplayIcon />}
            onClick={handleUploadAndMerge}
            disabled={uploading || selectedFiles.length === 0}
            sx={{
              borderRadius: '10px',
              fontWeight: 700,
              textTransform: 'none',
              px: 2.5,
              py: 1
            }}
          >
            {uploading ? 'Retrying...' : 'Retry Indexing'}
          </Button>
        </Paper>
      )}

      {/* Upload & Indexing Card */}
      <Paper
        variant="outlined"
        sx={{
          p: 3,
          borderRadius: '20px',
          backgroundColor: 'background.paper',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)',
          borderColor: 'divider',
        }}
      >
        <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
          <CloudUploadIcon color="primary" /> Select Log & Firmware Files
        </Typography>

        {/* Drag & Drop Area */}
        <Box
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragOver(true);
          }}
          onDragLeave={() => setIsDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          sx={{
            border: '2px dashed',
            borderColor: isDragOver ? 'primary.main' : 'divider',
            borderRadius: '16px',
            backgroundColor: isDragOver ? 'action.hover' : 'background.default',
            p: 4,
            textAlign: 'center',
            cursor: 'pointer',
            transition: 'all 0.2s ease-in-out',
            '&:hover': {
              borderColor: 'primary.light',
              backgroundColor: 'action.hover',
            },
          }}
        >
          <input
            type="file"
            multiple
            ref={fileInputRef}
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
          <CloudUploadIcon sx={{ fontSize: 44, color: isDragOver ? 'primary.main' : 'text.secondary', mb: 1 }} />
          <Typography variant="body1" sx={{ fontWeight: 600, color: 'text.primary' }}>
            Click to Browse or Drag & Drop log files here
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            Supports .txt, .log, .dmesg, .out, and raw ASCII console files
          </Typography>
        </Box>

        {/* Selected Files List */}
        {selectedFiles.length > 0 && (
          <Box sx={{ mt: 2.5 }}>
            <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.secondary', mb: 1 }}>
              Queued Files ({selectedFiles.length}):
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {selectedFiles.map((file, index) => (
                <Chip
                  key={index}
                  icon={<InsertDriveFileIcon />}
                  label={`${file.name} (${(file.size / 1024).toFixed(1)} KB)`}
                  onDelete={() => removeFile(index)}
                  deleteIcon={<DeleteOutlineIcon />}
                  variant="outlined"
                  sx={{ borderRadius: '8px', bgcolor: 'background.default' }}
                />
              ))}
            </Box>
          </Box>
        )}

        {/* Action Button */}
        <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
          {selectedFiles.length > 0 && (
            <Button
              variant="outlined"
              color="inherit"
              onClick={() => setSelectedFiles([])}
              sx={{ borderRadius: '10px' }}
            >
              Clear All
            </Button>
          )}
          <Button
            variant="contained"
            color="primary"
            onClick={handleUploadAndMerge}
            disabled={uploading || selectedFiles.length === 0}
            startIcon={uploading ? <CircularProgress size={18} color="inherit" /> : <CloudUploadIcon />}
            sx={{ borderRadius: '10px', px: 3, fontWeight: 600 }}
          >
            {uploading ? 'Merging & Indexing Files...' : 'Index & Prepare for Analysis'}
          </Button>
        </Box>
      </Paper>

      {/* Two Columns: AI Assistant vs Keyword Search */}
      <Grid container spacing={3}>
        {/* Left Column: AI Assistant */}
        <Grid item xs={12} lg={6}>
          <Paper
            ref={chatCardRef}
            variant="outlined"
            sx={{
              p: 3,
              borderRadius: '20px',
              backgroundColor: 'background.paper',
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)',
              borderColor: indexingStatus === 'success' ? '#86EFAC' : 'divider',
              transition: 'border-color 0.3s ease'
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
                <SmartToyIcon color="primary" /> AI Log Assistant
              </Typography>
              {indexingStatus === 'success' ? (
                <Chip
                  size="small"
                  icon={<CheckCircleIcon sx={{ fontSize: '14px !important', color: '#16A34A !important' }} />}
                  label="Indexed & Ready to Chat"
                  sx={{ borderRadius: '6px', fontWeight: 600, bgcolor: '#DCFCE7', color: '#15803D' }}
                />
              ) : indexingStatus === 'indexing' ? (
                <Chip
                  size="small"
                  icon={<CircularProgress size={12} color="inherit" />}
                  label="Indexing..."
                  color="primary"
                  variant="outlined"
                  sx={{ borderRadius: '6px' }}
                />
              ) : (
                <Chip
                  size="small"
                  label="Local LLM"
                  color="default"
                  variant="outlined"
                  sx={{ borderRadius: '6px' }}
                />
              )}
            </Box>

            {/* Quick Prompt Chips */}
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.8, mb: 2 }}>
              {quickPrompts.map((prompt, i) => (
                <Chip
                  key={i}
                  label={prompt}
                  size="small"
                  onClick={() => setChatQuery(prompt)}
                  sx={{
                    borderRadius: '8px',
                    fontSize: '11px',
                    cursor: 'pointer',
                    '&:hover': { bgcolor: 'action.hover' }
                  }}
                />
              ))}
            </Box>

            <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
              <TextField
                inputRef={chatInputRef}
                fullWidth
                size="small"
                multiline
                rows={2}
                placeholder={indexingStatus === 'success' ? "Ask any technical question about your indexed files..." : "Upload and index log files above first to chat..."}
                value={chatQuery}
                onChange={(e) => setChatQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleChatRequest();
                  }
                }}
                sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' } }}
              />
              <Button
                variant="contained"
                onClick={handleChatRequest}
                disabled={chatLoading || !chatQuery.trim()}
                sx={{ borderRadius: '12px', minWidth: '56px' }}
              >
                {chatLoading ? <CircularProgress size={20} color="inherit" /> : <SendIcon fontSize="small" />}
              </Button>
            </Box>

            {/* AI Response Display */}
            <Box sx={{ flexGrow: 1, minHeight: '220px' }}>
              {chatLoading && (
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 1.5 }}>
                  <CircularProgress size={24} />
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Reasoning over indexed logs...
                  </Typography>
                </Box>
              )}

              {!chatLoading && chatResponse && (
                <Paper
                  variant="outlined"
                  sx={{
                    p: 2.5,
                    borderRadius: '14px',
                    backgroundColor: '#0F172A',
                    color: '#F8FAFC',
                    position: 'relative',
                    maxHeight: '350px',
                    overflowY: 'auto'
                  }}
                >
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                    <Typography variant="caption" sx={{ color: '#94A3B8', fontWeight: 600 }}>
                      AI RESPONSE
                    </Typography>
                    <Tooltip title={copied ? 'Copied!' : 'Copy to Clipboard'}>
                      <IconButton
                        size="small"
                        onClick={() => copyToClipboard(chatResponse)}
                        sx={{ color: '#94A3B8', '&:hover': { color: '#F8FAFC' } }}
                      >
                        {copied ? <CheckCircleOutlineIcon fontSize="small" color="success" /> : <ContentCopyIcon fontSize="small" />}
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Typography
                    variant="body2"
                    sx={{
                      fontFamily: 'monospace',
                      fontSize: '12.5px',
                      lineHeight: 1.6,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {chatResponse}
                  </Typography>
                </Paper>
              )}

              {!chatLoading && !chatResponse && (
                <Box
                  sx={{
                    height: '100%',
                    minHeight: '160px',
                    border: '1px dashed',
                    borderColor: indexingStatus === 'success' ? '#86EFAC' : 'divider',
                    bgcolor: indexingStatus === 'success' ? 'rgba(240, 253, 244, 0.4)' : 'transparent',
                    borderRadius: '12px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    p: 3,
                    textAlign: 'center',
                    gap: 1
                  }}
                >
                  {indexingStatus === 'success' ? (
                    <>
                      <CheckCircleIcon sx={{ color: '#16A34A', fontSize: 32 }} />
                      <Typography variant="body2" sx={{ fontWeight: 600, color: '#14532D' }}>
                        Done indexing successfully! Start chatting
                      </Typography>
                      <Typography variant="caption" sx={{ color: '#166534', maxWidth: '360px' }}>
                        Your log files are active in local memory. Type your question above or click a prompt chip.
                      </Typography>
                    </>
                  ) : (
                    <>
                      <CloudUploadIcon sx={{ color: 'text.secondary', fontSize: 32 }} />
                      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                        Upload and click "Index & Prepare" above to vectorize your log files before chatting.
                      </Typography>
                    </>
                  )}
                </Box>
              )}
            </Box>
          </Paper>
        </Grid>

        {/* Right Column: Keyword Search */}
        <Grid item xs={12} lg={6}>
          <Paper
            variant="outlined"
            sx={{
              p: 3,
              borderRadius: '20px',
              backgroundColor: 'background.paper',
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 4px 20px rgba(0, 0, 0, 0.02)',
              borderColor: 'divider',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
                <SearchIcon color="primary" /> Fast Regex & Keyword Search
              </Typography>
              {searchResults.length > 0 && (
                <Chip size="small" label={`${searchResults.length} matches`} color="success" variant="outlined" sx={{ borderRadius: '6px' }} />
              )}
            </Box>

            <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search strings, tokens, errors (e.g., failed, kernel, eth0)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                sx={{ '& .MuiOutlinedInput-root': { borderRadius: '12px', bgcolor: 'background.default' } }}
              />
              <Button
                variant="contained"
                onClick={handleSearch}
                disabled={searching || !searchQuery.trim()}
                sx={{ borderRadius: '12px', px: 2.5, fontWeight: 600 }}
              >
                {searching ? <CircularProgress size={18} color="inherit" /> : 'Find'}
              </Button>
            </Box>

            {/* Results List */}
            <Box sx={{ flexGrow: 1, minHeight: '260px', maxHeight: '400px', overflowY: 'auto' }}>
              {searchResults.length > 0 ? (
                <List sx={{ p: 0 }}>
                  {searchResults.map((res, index) => (
                    <ListItem
                      key={index}
                      alignItems="flex-start"
                      sx={{
                        flexDirection: 'column',
                        p: 1.5,
                        mb: 1,
                        borderRadius: '10px',
                        border: '1px solid',
                        borderColor: 'divider',
                        backgroundColor: 'background.default',
                        '&:hover': { bgcolor: 'action.hover' }
                      }}
                    >
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', mb: 0.8 }}>
                        <Tooltip title={res.source || res.filename || 'Log Source'} arrow>
                          <Chip
                            size="small"
                            label={res.filename || res.source?.split(/[/\\]/).pop() || 'Log File'}
                            color="primary"
                            variant="outlined"
                            sx={{ height: '22px', fontSize: '11px', fontWeight: 600, maxWidth: '240px' }}
                          />
                        </Tooltip>
                        <Chip
                          size="small"
                          label={`Line #${res.line}`}
                          sx={{
                            height: '20px',
                            fontSize: '11px',
                            fontWeight: 700,
                            bgcolor: 'action.selected',
                            color: 'text.primary'
                          }}
                        />
                      </Box>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: 'monospace',
                          fontSize: '12px',
                          color: '#0F172A',
                          wordBreak: 'break-word',
                          whiteSpace: 'pre-wrap',
                          bgcolor: 'background.paper',
                          p: 1.2,
                          borderRadius: '6px',
                          width: '100%',
                          border: '1px solid',
                          borderColor: 'divider',
                        }}
                      >
                        {highlightMatch(res.content, searchQuery)}
                      </Typography>
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Box
                  sx={{
                    height: '100%',
                    minHeight: '200px',
                    border: '1px dashed',
                    borderColor: 'divider',
                    borderRadius: '12px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    p: 3,
                    textAlign: 'center'
                  }}
                >
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    {searching ? 'Querying index...' : 'Enter a search term above to locate specific occurrences across indexed logs.'}
                  </Typography>
                </Box>
              )}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default FileAnalysisComponent;
