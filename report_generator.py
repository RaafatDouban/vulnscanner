from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.reports_dir = 'reports'
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def generate_report(self, scan_results, target):
        """Generate a PDF report from scan results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.reports_dir}/vuln_scan_{target.replace('.', '_')}_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        elements.append(Paragraph(f"Vulnerability Scan Report", title_style))
        elements.append(Paragraph(f"Target: {target}", styles['Heading2']))
        elements.append(Paragraph(f"Scan Date: {scan_results['timestamp']}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Open Ports Section
        if scan_results.get('open_ports'):
            elements.append(Paragraph("Open Ports", styles['Heading2']))
            ports_data = [['Port', 'State', 'Service', 'Product', 'Version']]
            for port in scan_results['open_ports']:
                ports_data.append([
                    str(port['port']),
                    port['state'],
                    port['name'],
                    port['product'],
                    port['version']
                ])
            
            ports_table = Table(ports_data, colWidths=[1*inch, 1*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            ports_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(ports_table)
            elements.append(Spacer(1, 20))
        
        # Vulnerabilities Section
        if scan_results.get('vulnerabilities'):
            elements.append(Paragraph("Vulnerabilities", styles['Heading2']))
            vuln_data = [['Port', 'Service', 'Severity', 'Description', 'Recommendation']]
            for vuln in scan_results['vulnerabilities']:
                vuln_data.append([
                    str(vuln['port']),
                    vuln['service'],
                    vuln['severity'],
                    vuln['description'],
                    vuln['recommendation']
                ])
            
            vuln_table = Table(vuln_data, colWidths=[0.8*inch, 1*inch, 1*inch, 2*inch, 2*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(vuln_table)
        
        # Build PDF
        doc.build(elements)
        return filename 