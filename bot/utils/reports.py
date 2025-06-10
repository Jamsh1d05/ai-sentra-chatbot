import io
import os
import tempfile

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white, red, orange, green
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.flowables import Image, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from bot.api_services.virus_total import VirusTotalAPI 
from bot.config import redis_client, LANGUAGES, VIRUS_TOTAL_TOKEN
from datetime import datetime

vt_api = VirusTotalAPI(VIRUS_TOTAL_TOKEN)

COLORS = {
    'primary': HexColor('#1a365d'),      
    'secondary': HexColor('#2d3748'),    
    'success': HexColor('#38a169'),      
    'warning': HexColor('#ed8936'),      
    'danger': HexColor('#e53e3e'),       
    'light': HexColor('#f7fafc'),        
    'accent': HexColor('#3182ce')        
}

class SecurityReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=COLORS['primary'],
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            textColor=COLORS['primary'],
            spaceBefore=20,
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=COLORS['secondary'],
            spaceBefore=15,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        for level, color in [('HIGH', COLORS['danger']), ('MEDIUM', COLORS['warning']), ('LOW', COLORS['success'])]:
            self.styles.add(ParagraphStyle(
                name=f'Risk{level}',
                parent=self.styles['Normal'],
                fontSize=14,
                textColor=color,
                fontName='Helvetica-Bold'
            ))

    def _fmt_timestamp(self, ts):
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC") if ts else "N/A"
    
    def _get_threat_level(self, malicious_count, total_count):
        if total_count == 0:
            return "UNKNOWN", COLORS['secondary']
        
        ratio = malicious_count / total_count
        if ratio >= 0.3:  # 30% or more engines detect as malicious
            return "HIGH", COLORS['danger']
        elif ratio >= 0.1:  # 10-29% detection
            return "MEDIUM", COLORS['warning']
        elif ratio > 0:    # Some detection but low
            return "LOW", COLORS['warning']
        else:
            return "CLEAN", COLORS['success']
    
    def _create_header(self):
        """Create report header"""
        title_para = Paragraph('🛡️ CYBERSECURITY THREAT ANALYSIS REPORT', 
                              ParagraphStyle('HeaderTitle', 
                                           parent=self.styles['Normal'],
                                           fontSize=14,
                                           fontName='Helvetica-Bold',
                                           textColor=white,
                                           alignment=TA_CENTER))
        
        generated_para = Paragraph(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}',
                                 ParagraphStyle('HeaderInfo',
                                              parent=self.styles['Normal'],
                                              fontSize=9,
                                              fontName='Helvetica',
                                              textColor=COLORS['secondary']))
        
        classification_para = Paragraph('Classification: TLP:WHITE',
                                      ParagraphStyle('HeaderClass',
                                                   parent=self.styles['Normal'],
                                                   fontSize=9,
                                                   fontName='Helvetica',
                                                   textColor=COLORS['secondary'],
                                                   alignment=TA_RIGHT))
        
        header_data = [
            [title_para, ''],
            [generated_para, classification_para]
        ]
        
        header_table = Table(header_data, colWidths=[4.5*inch, 2*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
            ('SPAN', (0, 0), (1, 0)), 
            ('ALIGN', (0, 0), (0, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, 1), COLORS['light']),
            ('GRID', (0, 0), (-1, -1), 1, COLORS['secondary']),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8)
        ]))
        return header_table
    
    def _create_executive_summary(self, input_type, query, threat_level, malicious_count, total_count):
        summary_text = f"""
        This report presents a comprehensive security analysis of the <b>{input_type}</b>\n <b>{query}</b>\n 
        conducted using VirusTotal's multi-engine scanning platform. The analysis utilized 
        <i>{total_count}</i> security engines to assess potential threats and malicious indicators.\n
        
        <b>Key Findings:</b><br/>
        <b>• Threat Level:</b> <font color="{threat_level[1].hexval()}">{threat_level[0]}</font><br/>
        <b>• Detection Ratio:</b> {malicious_count}/{total_count} engines flagged as malicious<br/>
        <b>• Analysis Date:</b> {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}<br/>
        """
        
        return Paragraph(summary_text, self.styles['Normal'])
    
    def _create_detection_chart(self, stats):
        drawing = Drawing(300, 200)
        
        pie = Pie()
        pie.x = 50
        pie.y = 50
        pie.width = 150
        pie.height = 150
        
        labels = []
        data = []
        colors = []
        
        if stats.get('malicious', 0) > 0:
            labels.append('Malicious')
            data.append(stats['malicious'])
            colors.append(COLORS['danger'])
        
        if stats.get('suspicious', 0) > 0:
            labels.append('Suspicious')
            data.append(stats['suspicious'])
            colors.append(COLORS['warning'])
        
        clean_count = stats.get('harmless', 0) + stats.get('undetected', 0)
        if clean_count > 0:
            labels.append('Clean')
            data.append(clean_count)
            colors.append(COLORS['success'])
        
        pie.data = data
        pie.labels = labels
        pie.slices.strokeColor = white
        pie.slices.strokeWidth = 2
        
        for i, color in enumerate(colors):
            pie.slices[i].fillColor = color
        
        drawing.add(pie)
        return drawing
    
    def _create_detailed_analysis_table(self, input_type, attributes):
        if input_type == "hash":
            data = [
                ['Attribute', 'Value'],
                ['SHA256', attributes.get('sha256', 'N/A')],
                ['SHA1', attributes.get('sha1', 'N/A')],
                ['MD5', attributes.get('md5', 'N/A')],
                ['File Size', f"{attributes.get('size', 'Unknown')} bytes"],
                ['File Type', attributes.get('type_description', 'Unknown')],
                ['First Submission', self._fmt_timestamp(attributes.get('first_submission_date'))],
                ['Last Analysis', self._fmt_timestamp(attributes.get('last_analysis_date'))],
                ['Reputation Score', str(attributes.get('reputation', 'N/A'))]
            ]
        elif input_type == "ip":
            data = [
                ['Attribute', 'Value'],
                ['IP Address', attributes.get('ip_address', 'N/A')],
                ['Country', attributes.get('country', 'Unknown')],
                ['ASN', str(attributes.get('asn', 'Unknown'))],
                ['Network', attributes.get('network', 'Unknown')],
                ['Regional Internet Registry', attributes.get('regional_internet_registry', 'Unknown')],
                ['Last Analysis', self._fmt_timestamp(attributes.get('last_analysis_date'))],
                ['Reputation Score', str(attributes.get('reputation', 'N/A'))]
            ]
        elif input_type == "domain":
            data = [
                ['Attribute', 'Value'],
                ['Domain', attributes.get('id', 'N/A')],
                ['Registrar', attributes.get('registrar', 'Unknown')],
                ['Creation Date', self._fmt_timestamp(attributes.get('creation_date'))],
                ['Last Update', self._fmt_timestamp(attributes.get('last_modification_date'))],
                ['Expiration Date', self._fmt_timestamp(attributes.get('expiration_date'))],
                ['Last Analysis', self._fmt_timestamp(attributes.get('last_analysis_date'))],
                ['Reputation Score', str(attributes.get('reputation', 'N/A'))]
            ]
        elif input_type == "url":
            data = [
                ['Attribute', 'Value'],
                ['URL', attributes.get('url', 'N/A')],
                ['Final URL', attributes.get('last_final_url', 'N/A')],
                ['Title', attributes.get('title', 'N/A')],
                ['First Submission', self._fmt_timestamp(attributes.get('first_submission_date'))],
                ['Last Analysis', self._fmt_timestamp(attributes.get('last_analysis_date'))],
                ['Threat Classification', attributes.get('popular_threat_classification', {}).get('suggested_threat_label', 'None')],
                ['Reputation Score', str(attributes.get('reputation', 'N/A'))]
            ]
        
        table = Table(data, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (0, -1), COLORS['light']),
            ('GRID', (0, 0), (-1, -1), 1, COLORS['secondary']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, COLORS['light']])
        ]))
        return table
    
    def _create_detection_details_table(self, attributes, limit=10):
        detection_data = [['Security Engine', 'Result', 'Category', 'Engine Version']]
        
        results = attributes.get('last_analysis_results', {})
        malicious_results = []
        
        for engine, result in results.items():
            if result.get('category') == 'malicious' and result.get('result'):
                malicious_results.append([
                    engine,
                    result.get('result', 'Detected'),
                    'Malicious',
                    result.get('engine_version', 'N/A')
                ])
        
        for engine, result in results.items():
            if len(malicious_results) >= limit:
                break
            if result.get('category') == 'suspicious' and result.get('result'):
                malicious_results.append([
                    engine,
                    result.get('result', 'Suspicious'),
                    'Suspicious',
                    result.get('engine_version', 'N/A')
                ])
        
        detection_data.extend(malicious_results[:limit])
        
        if not malicious_results:
            detection_data.append(['No malicious detections found', '', '', ''])
        
        table = Table(detection_data, colWidths=[1.5*inch, 2.5*inch, 1*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, COLORS['secondary']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, COLORS['light']]),
            ('FONTSIZE', (0, 1), (-1, -1), 9)
        ]))
        
        for i, row in enumerate(malicious_results[:limit], 1):
            if 'Malicious' in row:
                table.setStyle(TableStyle([
                    ('TEXTCOLOR', (2, i), (2, i), COLORS['danger'])
                ]))
            elif 'Suspicious' in row:
                table.setStyle(TableStyle([
                    ('TEXTCOLOR', (2, i), (2, i), COLORS['warning'])
                ]))
        
        return table
    
    def _create_recommendations_section(self, threat_level, input_type):
        recommendations = {
            'HIGH': [
                'Immediate isolation of affected systems',
                'Block the suspicious entity at network perimeter',
                'Conduct thorough system scan and forensic analysis',
                'Review security logs for indicators of compromise',
                'Consider incident response procedures activation'
            ],
            'MEDIUM': [
                'Monitor systems for suspicious activity',
                'Consider blocking or restricting access',
                'Increase logging and monitoring',
                'Review security policies and controls',
                'Schedule additional security scans'
            ],
            'LOW': [
                'Continue monitoring with standard procedures',
                'Document findings for future reference',
                'Maintain current security posture',
                'Regular security assessments recommended'
            ],
            'CLEAN': [
                'No immediate action required',
                'Continue regular security monitoring',
                'Maintain security best practices',
                'Periodic reassessment recommended'
            ]
        }
        
        recs = recommendations.get(threat_level[0], recommendations['LOW'])
        rec_text = '<br/>'.join([f'• {rec}' for rec in recs])
        
        return Paragraph(f'<b>Recommended Actions:</b><br/>{rec_text}', self.styles['Normal'])

    def generate_vt_pdf(self, input_type, query, attributes):
        safe_query = query.replace('/', '_').replace(':', '_').replace('\\', '_').replace('?', '_').replace('*', '_')[:20]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"virustotal_report_{safe_query}_{timestamp}.pdf"
        
        temp_dir = tempfile.gettempdir()
        tmp_path = os.path.join(temp_dir, filename)
        
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        
        doc = SimpleDocTemplate(tmp_path, pagesize=A4, 
                              rightMargin=72, leftMargin=72, 
                              topMargin=72, bottomMargin=18)
        
        story = []
        
        story.append(self._create_header())
        story.append(Spacer(1, 20))
        
        stats = attributes.get("last_analysis_stats", {})
        total_engines = sum(stats.values())
        malicious_count = stats.get("malicious", 0)
        threat_level = self._get_threat_level(malicious_count, total_engines)
        
        story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        story.append(self._create_executive_summary(input_type, query, threat_level, malicious_count, total_engines))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("DETECTION OVERVIEW", self.styles['SectionHeader']))
        
        risk_text = f'<b>THREAT LEVEL: <font color="{threat_level[1].hexval()}">{threat_level[0]}</font></b><br/><b>Detection Ratio:</b><b>{malicious_count}/{total_engines}</b> engines'
        story.append(Paragraph(risk_text, self.styles['Normal']))
        story.append(Spacer(1, 10))
        
    
        if total_engines > 0:
            story.append(self._create_detection_chart(stats))
            story.append(Spacer(1, 20))
        
        story.append(Paragraph("DETAILED ANALYSIS", self.styles['SectionHeader']))
        story.append(self._create_detailed_analysis_table(input_type, attributes))
        story.append(Spacer(1, 20))
        
        if malicious_count > 0:
            story.append(Paragraph("SECURITY ENGINE DETECTIONS", self.styles['SectionHeader']))
            story.append(self._create_detection_details_table(attributes))
            story.append(Spacer(1, 20))
        
        story.append(Paragraph("SECURITY RECOMMENDATIONS", self.styles['SectionHeader']))
        story.append(self._create_recommendations_section(threat_level, input_type))
        story.append(Spacer(1, 20))
        
        footer_text = """
        <b>DISCLAIMER:</b> This report is generated based on VirusTotal analysis results. 
        Results may vary and should be correlated with additional security tools and analysis. 
        This report is for informational purposes only.<br/><br/>
        
        <b>Report ID:</b> VT-{timestamp}<br/>
        <b>Classification:</b> TLP:WHITE
        """.format(timestamp=datetime.now().strftime('%Y%m%d%H%M%S'))
        
        story.append(Paragraph(footer_text, self.styles['Normal']))
        
        doc.build(story)
        return tmp_path

