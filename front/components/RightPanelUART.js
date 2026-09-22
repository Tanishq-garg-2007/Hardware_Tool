import React, { useState, useEffect } from 'react';
import { Box, Grid, Typography, Paper } from '@mui/material';
import CaptureBootLogs from './CaptureBootLogs';
import CheckUARTConsole from './CheckUARTConsole';
import DetectBaudrate from './DetectBaudrate';
import AnalyzeBootLog from './AnalyzeBootLog.js';
import VoltageGlitcher from './VoltageGlitcher';
import NewVoltageGlitcher from './NewVoltageGlitcher';
import BasicAccordion from './BasicAccordian';
import NewCaptureBootLog from './NewCaptureBootLog';
import NewDetectBaudrate from './NewDetectBaudrate';
import NewCheckUARTConsole from './NewCheckUARTConsole';

const RightPanelUART = ({ currentModule }) => {
  const [report, setReport] = useState();
  const [list, setList] = useState([]);

  let content = (
    <Box sx={{ textAlign: 'center', py: 8, color: 'text.secondary' }}>
      <Typography variant="h5" sx={{ mb: 1, fontWeight: 600, color: 'text.primary' }}>
        Select a Hardware Module
      </Typography>
      <Typography variant="body1">
        Choose a tool from the left navigation panel to configure parameters and run hardware tests.
      </Typography>
    </Box>
  );

  if (currentModule === 'Voltage Glitcher') {
    content = <VoltageGlitcher />;
  } else if (currentModule === 'Detect Baudrate') {
    content = <DetectBaudrate setReport={setReport} />;
  } else if (currentModule === 'Check For UART Console') {
    content = <CheckUARTConsole />;
  } else if (currentModule === 'Capture Boot Logs' || currentModule === 'Captue Boot Logs') {
    content = <CaptureBootLogs />;
  } else if (currentModule === 'Analyze Boot Logs' || currentModule === 'New Analyze Boot Logs') {
    content = <AnalyzeBootLog />;
  } else if (currentModule === 'New Voltage Glitcher') {
    content = <NewVoltageGlitcher />;
  } else if (currentModule === 'New Capture BootLog') {
    content = <NewCaptureBootLog />;
  } else if (currentModule === 'New Detect Baudrate') {
    content = <NewDetectBaudrate setReport={setReport} />;
  } else if (currentModule === 'New Check for UART Analysis') {
    content = <NewCheckUARTConsole />;
  }

  useEffect(() => {
    if (currentModule !== 'Detect Baudrate' && currentModule !== 'New Detect Baudrate') {
      setReport(null);
      setList([]);
    }
  }, [currentModule]);

  useEffect(() => {
    const generateFormatedList = () => {
      if (!report) {
        setList([]);
        return;
      }
      const lines = report.split('\n');

      let result = [];
      let currentTitle = '';
      let currentContent = '';

      for (const line of lines) {
        if (line.includes('USING ')) {
          if (currentTitle !== '' && currentContent !== '') {
            if (currentContent.length < 50) {
              result.push({ title: currentTitle, content: 'This is not the correct baud rate.' });
            } else {
              result.push({ title: currentTitle, content: currentContent });
            }
          }
          currentTitle = line.trim();
          currentContent = '';
          const match = line.match(/\d+/);
          const numericalValue = match ? parseInt(match[0], 10) : '';
          currentTitle = 'Using Baudrate: ' + numericalValue;
        } else {
          currentContent += line + '\n';
        }
      }

      if (currentTitle !== '' && currentContent !== '') {
        if (currentContent.length < 50) {
          result.push({ title: currentTitle, content: 'This is not the correct baud rate.' });
        } else {
          result.push({ title: currentTitle, content: currentContent });
        }
      }

      setList(result);
    };
    generateFormatedList();
  }, [report]);

  const isBaudrateModule = currentModule === 'Detect Baudrate' || currentModule === 'New Detect Baudrate';

  return (
    <Grid item xs={12} md={8} lg={9}>
      <Paper
        elevation={0}
        sx={{
          backgroundColor: 'background.paper',
          borderRadius: '24px',
          p: { xs: 3, md: 4 },
          border: '1px solid',
          borderColor: 'divider',
          boxShadow: '0 4px 30px rgba(0, 0, 0, 0.03)',
          minHeight: '600px',
          display: 'flex',
          flexDirection: 'column',
          gap: 3,
        }}
      >
        {currentModule && currentModule !== 'none' && (
          <Box sx={{ borderBottom: '1px solid', borderColor: 'divider', pb: 2 }}>
            <Typography variant="h3" sx={{ color: 'text.primary', fontSize: '22px', fontWeight: 600 }}>
              {currentModule}
            </Typography>
          </Box>
        )}

        <Box sx={{ width: '100%' }}>{content}</Box>

        {isBaudrateModule && list && list.length > 0 && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600, color: 'text.primary' }}>
              Detected Baudrate Output Log
            </Typography>
            <BasicAccordion list={list} />
          </Box>
        )}
      </Paper>
    </Grid>
  );
};

export default RightPanelUART;
