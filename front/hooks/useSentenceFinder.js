import { useState } from 'react';

const useSentenceFinder = () => {
    const [sentenses, setSentences] = useState([]);

    const findSentences = (report, keyword1) => {
        if (!report || typeof report !== 'string') {
            setSentences([]);
            return;
        }

        if (!Array.isArray(keyword1) || keyword1.length === 0) {
            setSentences([]);
            return;
        }

        const lines = report.split('\n');
        const matchedSet = new Set();
        const sentencesArr = [];

        keyword1.forEach((keyword) => {
            if (!keyword || !keyword.trim()) return;
            const escaped = keyword.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            try {
                const regex = new RegExp(`(^|[^a-zA-Z0-9_-])${escaped}([^a-zA-Z0-9_-]|$)`, 'i');
                lines.forEach((line) => {
                    const trimmed = line.trim();
                    if (trimmed && regex.test(trimmed) && !matchedSet.has(trimmed)) {
                        matchedSet.add(trimmed);
                        sentencesArr.push(trimmed);
                    }
                });
            } catch (_) {}
        });

        setSentences(sentencesArr);
    };

    return {
        findSentences,
        sentenses
    };
};

export default useSentenceFinder;
