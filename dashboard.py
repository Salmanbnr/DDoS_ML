import dash
from dash import dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from datetime import datetime, timedelta
import threading
import time

from traffic_capture import TrafficCapture
from ddos_detector import DDoSDetector

# Initialize the detector
detector = DDoSDetector()

# Define colors
COLORS = {
    'background': '#0a0e27',
    'card_bg': '#1a1f3a',
    'text': '#ffffff',
    'accent': '#00d9ff',
    'danger': '#ff4444',
    'warning': '#ffaa00',
    'success': '#00ff88',
    'benign': '#00ff88',
    'ddos': '#ff4444'
}

# Helper functions
def create_stat_card(title, card_id, icon, color):
    return dbc.Card([
        dbc.CardBody([
            html.Div([
                html.I(className=f"{icon} fa-2x mb-2", style={'color': color}),
                html.H4(title, className='text-muted mb-2'),
                html.H2(id=card_id, children='0', style={'color': color, 'fontWeight': 'bold'})
            ], style={'textAlign': 'center'})
        ])
    ], style={'backgroundColor': COLORS['card_bg'], 'border': f'1px solid {color}'})


def create_graph_card(title, graph_id):
    return dbc.Card([
        dbc.CardHeader(html.H5(title, style={'color': COLORS['text']})),
        dbc.CardBody([
            dcc.Graph(id=graph_id, style={'height': '300px'})
        ])
    ], style={'backgroundColor': COLORS['card_bg'], 'border': f'1px solid {COLORS["accent"]}'})


def create_table_card(title, table_id):
    return dbc.Card([
        dbc.CardHeader(html.H5(title, style={'color': COLORS['text']})),
        dbc.CardBody([
            html.Div(id=table_id, style={'maxHeight': '300px', 'overflowY': 'auto'})
        ])
    ], style={'backgroundColor': COLORS['card_bg'], 'border': f'1px solid {COLORS["accent"]}'})


def create_empty_figure(message):
    fig = go.Figure()
    fig.add_annotation(text=message, xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(size=16, color=COLORS['text']))
    fig.update_layout(template='plotly_dark', paper_bgcolor=COLORS['card_bg'], plot_bgcolor=COLORS['card_bg'], xaxis=dict(visible=False), yaxis=dict(visible=False), margin=dict(l=40, r=40, t=40, b=40))
    return fig


def detection_callback(features_df, flow_id, packet_info):
    detector.predict(features_df, flow_id, packet_info)


capture = TrafficCapture(interface='lo', callback=detection_callback)

app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.CYBORG,
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
    ],
    suppress_callback_exceptions=True
)

app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H1([html.I(className="fas fa-shield-alt me-3"), "DDoS Detection System - SOC Dashboard"], style={'color': COLORS['accent'], 'textAlign': 'center', 'fontWeight': 'bold', 'marginBottom': '10px'}),
                html.P("Real-time Network Traffic Analysis & Threat Detection", style={'textAlign': 'center', 'color': COLORS['text'], 'opacity': '0.8'})
            ])
        ], width=12)
    ], className='mb-4 mt-3'),
    
    dbc.Row([
        dbc.Col([
            dbc.ButtonGroup([
                dbc.Button([html.I(className="fas fa-play me-2"), "Start Capture"], id='start-btn', color='success', n_clicks=0),
                dbc.Button([html.I(className="fas fa-stop me-2"), "Stop Capture"], id='stop-btn', color='danger', n_clicks=0),
                dbc.Button([html.I(className="fas fa-redo me-2"), "Reset Stats"], id='reset-btn', color='warning', n_clicks=0),
            ])
        ], width=12, className='text-center mb-4')
    ]),
    
    html.Div(id='status-message', className='mb-3'),
    
    dbc.Row([
        dbc.Col([create_stat_card("Total Packets", "total-packets", "fas fa-network-wired", COLORS['accent'])], width=3),
        dbc.Col([create_stat_card("Active Flows", "active-flows", "fas fa-stream", COLORS['warning'])], width=3),
        dbc.Col([create_stat_card("Benign Traffic", "benign-count", "fas fa-check-circle", COLORS['success'])], width=3),
        dbc.Col([create_stat_card("DDoS Detected", "ddos-count", "fas fa-exclamation-triangle", COLORS['danger'])], width=3),
    ], className='mb-4'),
    
    dbc.Row([
        dbc.Col([create_stat_card("Detection Rate", "detection-rate", "fas fa-percentage", COLORS['warning'])], width=6),
        dbc.Col([create_stat_card("Packets/Second", "packets-per-sec", "fas fa-tachometer-alt", COLORS['accent'])], width=6),
    ], className='mb-4'),
    
    dbc.Row([
        dbc.Col([create_graph_card("Detection Timeline", 'detection-timeline')], width=8),
        dbc.Col([create_graph_card("Traffic Distribution", 'traffic-distribution')], width=4),
    ], className='mb-4'),
    
    dbc.Row([
        dbc.Col([create_table_card("Active Threats", 'active-threats-table')], width=6),
        dbc.Col([create_table_card("Recent Detections", 'recent-detections-table')], width=6),
    ], className='mb-4'),
    
    dbc.Row([
        dbc.Col([create_table_card("Recent Network Packets", 'recent-packets-table')], width=12),
    ], className='mb-4'),
    
    dcc.Interval(id='interval-component', interval=1000, n_intervals=0),
    
], fluid=True, style={'backgroundColor': COLORS['background'], 'minHeight': '100vh', 'padding': '20px'})


@app.callback(
    Output('status-message', 'children'),
    [Input('start-btn', 'n_clicks'), Input('stop-btn', 'n_clicks'), Input('reset-btn', 'n_clicks')],
    prevent_initial_call=True
)
def control_capture(start, stop, reset):
    ctx = dash.callback_context
    if not ctx.triggered: return ""
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'start-btn':
        if not capture.running:
            capture.start()
            return dbc.Alert("Capture started!", color="success", duration=3000)
    elif button_id == 'stop-btn':
        if capture.running:
            capture.stop()
            return dbc.Alert("Capture stopped!", color="info", duration=3000)
    elif button_id == 'reset-btn':
        detector.reset_stats()
        return dbc.Alert("Statistics reset!", color="info", duration=3000)
    return ""


@app.callback(
    [Output('total-packets', 'children'), Output('active-flows', 'children'), Output('benign-count', 'children'), Output('ddos-count', 'children'), Output('detection-rate', 'children'), Output('packets-per-sec', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_stats(n):
    c_stats = capture.get_stats()
    d_stats = detector.get_stats()
    return f"{c_stats['total_packets']:,}", f"{c_stats['total_flows']:,}", f"{d_stats['benign_count']:,}", f"{d_stats['ddos_count']:,}", f"{d_stats['detection_rate']*100:.1f}%", f"{c_stats['packets_per_second']:,}"


@app.callback(Output('detection-timeline', 'figure'), [Input('interval-component', 'n_intervals')])
def update_timeline(n):
    timeline_data = detector.get_timeline_data(minutes=5)
    if not timeline_data: return create_empty_figure("Waiting for data...")
    
    fig = go.Figure()
    # Logic for benign/ddos scatter trace
    fig.update_layout(template='plotly_dark', paper_bgcolor=COLORS['card_bg'], plot_bgcolor=COLORS['card_bg'], margin=dict(l=40, r=40, t=40, b=40), yaxis=dict(range=[0, 1]))
    return fig


@app.callback(Output('traffic-distribution', 'figure'), [Input('interval-component', 'n_intervals')])
def update_distribution(n):
    stats = detector.get_stats()
    if stats['benign_count'] == 0 and stats['ddos_count'] == 0: return create_empty_figure("No data")
    fig = go.Figure(data=[go.Pie(labels=['Benign', 'DDoS'], values=[stats['benign_count'], stats['ddos_count']], marker=dict(colors=[COLORS['benign'], COLORS['ddos']]), hole=0.4)])
    fig.update_layout(template='plotly_dark', paper_bgcolor=COLORS['card_bg'], plot_bgcolor=COLORS['card_bg'], margin=dict(l=20, r=20, t=20, b=20))
    return fig


@app.callback(Output('active-threats-table', 'children'), [Input('interval-component', 'n_intervals')])
def update_threats_table(n):
    threats = detector.get_active_threats()
    if not threats: return html.P("No threats", style={'textAlign': 'center', 'color': COLORS['success']})
    
    table_header = [html.Thead(html.Tr([html.Th("Source IP"), html.Th("Count"), html.Th("Probability"), html.Th("Severity")]))]
    rows = [html.Tr([html.Td(t['src_ip']), html.Td(t['count']), html.Td(f"{t['max_probability']*100:.1f}%"), html.Td(t['severity'].upper())]) for t in threats[:10]]
    
    return dbc.Table(table_header + [html.Tbody(rows)], bordered=True, color='dark', hover=True, responsive=True, striped=True, style={'fontSize': '0.9rem'})


@app.callback(Output('recent-detections-table', 'children'), [Input('interval-component', 'n_intervals')])
def update_detections_table(n):
    detections = detector.get_recent_detections(10)
    if not detections: return html.P("No detections yet")
    
    table_header = [html.Thead(html.Tr([html.Th("Time"), html.Th("Type"), html.Th("Probability"), html.Th("Source")]))]
    rows = [html.Tr([html.Td(datetime.fromisoformat(d['timestamp']).strftime('%H:%M:%S')), html.Td(d['prediction_label']), html.Td(f"{d['probability']*100:.1f}%"), html.Td(d['src_ip'])]) for d in reversed(detections)]
    
    return dbc.Table(table_header + [html.Tbody(rows)], bordered=True, color='dark', hover=True, responsive=True, striped=True, style={'fontSize': '0.9rem'})


@app.callback(Output('recent-packets-table', 'children'), [Input('interval-component', 'n_intervals')])
def update_packets_table(n):
    packets = capture.get_recent_packets(15)
    if not packets: return html.P("No packets captured")
    
    table_header = [html.Thead(html.Tr([html.Th("Time"), html.Th("Src"), html.Th("Dst"), html.Th("Prot"), html.Th("Len")]))]
    rows = [html.Tr([html.Td(datetime.fromisoformat(p['timestamp']).strftime('%H:%M:%S')), html.Td(p['src_ip']), html.Td(p['dst_ip']), html.Td(p['protocol']), html.Td(f"{p['length']}B")]) for p in reversed(packets)]
    
    return dbc.Table(table_header + [html.Tbody(rows)], bordered=True, color='dark', hover=True, responsive=True, striped=True, style={'fontSize': '0.9rem'})


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=8050)