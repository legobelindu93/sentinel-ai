
import jsPDF from 'jspdf';
import type { AnalysisResult } from '../types/scanner';

export const generatePDFReport = (result: AnalysisResult) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 20;
    let y = 20;

    const addText = (text: string, fontSize: number, fontStyle: string = 'normal', color: [number, number, number] = [0, 0, 0]) => {
        doc.setFontSize(fontSize);
        doc.setFont('helvetica', fontStyle);
        doc.setTextColor(color[0], color[1], color[2]);

        const splitText = doc.splitTextToSize(text, pageWidth - (margin * 2));
        doc.text(splitText, margin, y);
        y += (splitText.length * fontSize * 0.5) + 5;
    };

    const addLine = () => {
        doc.setDrawColor(200, 200, 200);
        doc.line(margin, y, pageWidth - margin, y);
        y += 10;
    };

    // --- HEADER ---
    doc.setFillColor(23, 23, 23); // Dark background
    doc.rect(0, 0, pageWidth, 40, 'F');

    doc.setFontSize(22);
    doc.setTextColor(168, 85, 247); // Purple
    doc.setFont('helvetica', 'bold');
    doc.text('SENTINEL', margin, 25);
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'normal');
    doc.text('core', margin + 38, 25);

    doc.setFontSize(10);
    doc.setTextColor(150, 150, 150);
    doc.text('FORENSIC ANALYSIS REPORT', pageWidth - margin - 60, 25);

    y = 50;

    // --- META INFO ---
    addText(`Target Repository: ${result.repoName}`, 12, 'bold');
    addText(`Scan Date: ${new Date().toLocaleString()}`, 10, 'normal', [100, 100, 100]);
    y += 5;

    // --- VERDICT SECTION ---
    const verdictColor: [number, number, number] =
        result.verdict === 'MALICIOUS' ? [220, 38, 38] : // Red
            result.verdict === 'SUSPICIOUS' ? [245, 158, 11] : // Orange
                result.verdict === 'DUAL-USE' ? [59, 130, 246] : // Blue
                    [16, 185, 129]; // Green

    doc.setFillColor(verdictColor[0], verdictColor[1], verdictColor[2]); // Verdict bg
    doc.roundedRect(margin, y, pageWidth - (margin * 2), 35, 3, 3, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(10);
    doc.text("FINAL VERDICT", margin + 10, y + 10);

    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text(result.verdict, margin + 10, y + 22);

    // Score Circle (Simulated)
    doc.setFontSize(30);
    doc.text(`${result.score}`, pageWidth - margin - 40, y + 22);
    doc.setFontSize(10);
    doc.text("/ 100", pageWidth - margin - 25, y + 22);

    y += 45;

    // --- CONTEXT & SUMMARY ---
    addText("CONTEXTUAL ANALYSIS", 14, 'bold', [50, 50, 50]);
    addLine();

    addText(`Detected Project Type: ${result.projectContext.type.toUpperCase()}`, 11, 'bold');
    if (result.projectContext.detectedFrameworks.length > 0) {
        addText(`Frameworks: ${result.projectContext.detectedFrameworks.join(', ')}`, 10);
    }
    y += 5;

    addText("EXPERT EXPLANATION", 12, 'bold', [80, 80, 80]);
    addText(result.explanation, 10, 'italic', [60, 60, 60]);
    y += 10;

    // --- KEY FINDINGS ---
    if (result.attackChain.length > 0) {
        doc.setFillColor(254, 242, 242); // Light red
        doc.setDrawColor(220, 38, 38);
        doc.roundedRect(margin, y, pageWidth - (margin * 2), (result.attackChain.length * 10) + 20, 2, 2, 'FD');

        y += 10;
        doc.setTextColor(220, 38, 38);
        doc.setFontSize(12);
        doc.setFont('helvetica', 'bold');
        doc.text("CRITICAL KILL CHAINS DETECTED", margin + 5, y);
        y += 10;

        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        result.attackChain.forEach(chain => {
            doc.text(`• ${chain}`, margin + 10, y);
            y += 7;
        });
        y += 10;
    }

    addText("OBSERVED BEHAVIORS", 12, 'bold', [50, 50, 50]);
    const behaviors = result.behaviors.join(', ');
    addText(behaviors || "No suspicious behaviors observed.", 10, 'normal');
    y += 10;

    // --- EVIDENCE TABLE ---
    addText("FORENSIC EVIDENCE", 14, 'bold', [50, 50, 50]);
    addLine();

    if (result.matches.length === 0) {
        addText("No threats detected in codebase.", 10, 'italic');
    } else {
        result.matches.forEach((match) => {
            // Page Break Check
            if (y > 250) {
                doc.addPage();
                y = 20;
            }

            // Evidence Block
            const severityColor = match.severity === 'critical' ? [220, 38, 38] : match.severity === 'high' ? [234, 88, 12] : [59, 130, 246];

            doc.setDrawColor(230, 230, 230);
            doc.setFillColor(250, 250, 250);
            doc.rect(margin, y, pageWidth - (margin * 2), 25, 'FD');

            // Sidebar Color
            doc.setFillColor(severityColor[0] as number, severityColor[1] as number, severityColor[2] as number);
            doc.rect(margin, y, 2, 25, 'F');

            doc.setFontSize(9);
            doc.setTextColor(100, 100, 100);
            doc.text(`${match.capability.toUpperCase()} | ${match.severity.toUpperCase()}`, margin + 5, y + 8);

            doc.setFontSize(10);
            doc.setTextColor(0, 0, 0);
            // Truncate file path if too long
            const fileName = match.file.length > 50 ? '...' + match.file.slice(-50) : match.file;
            doc.text(`${fileName}:${match.line}`, margin + 5, y + 15);

            doc.setFont('courier', 'normal');
            doc.setFontSize(8);
            doc.setTextColor(80, 80, 80);
            const snippet = match.content.length > 80 ? match.content.substring(0, 80) + '...' : match.content;
            doc.text(snippet, margin + 5, y + 22);

            y += 30;
        });
    }

    // Save
    const safeName = result.repoName.replace(/\//g, '_');
    doc.save(`SENTINEL_Report_${safeName}_${Date.now()}.pdf`);
};
