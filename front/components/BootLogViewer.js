import React from 'react';

const BootLogViewer = ({ children }) => {
  // Remove the irrelevant portion from the start of the bootlog
  if(!children) return <></>
  let bootlogToDisplay = children;



  // Split the bootlog into lines for processing
  const lines = bootlogToDisplay.split('\n');

  // Create an array to hold formatted lines
  const formattedLines = [];

  // Define keywords to highlight
  const highlightKeywords = [
    'RealTek(RTL8196E)',
    'CPU revision is',
    'Memory:',
    'Kernel command line:',
    'flash device:',
    'Creating 7 MTD partitions on',
    'SPI flash(MX25L3206E) was found',
    'NET: Registered protocol family',
    'Initializing device..',
    'eth0 added.',
    'eth1 added.',
    'PPP generic driver version',
    'MPPE/MPPC encryption/compression module registered',
    'Realtek WLAN driver-version',
    'MACFM software_init',
    'Probing RTL8186 10/100 NIC',
  ];

  // Process each line and apply formatting
  lines.forEach((line, index) => {
    let formattedLine = line;

    // Check if the line contains any of the highlight keywords
    highlightKeywords.forEach(keyword => {
      if (line.includes(keyword)) {
        const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        formattedLine = formattedLine.replace(
          new RegExp(escaped, 'g'),
          `<span class="highlight">${keyword}</span>`
        );
      }
    });

    // Add the formatted line to the array
    formattedLines.push(
      <div key={index} dangerouslySetInnerHTML={{ __html: formattedLine }} />
    );
  });

  return <div className="bootlog-wrapper">{formattedLines}</div>;
};

export default BootLogViewer
