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

# Helper functions - DEFINED BEFORE USE
def create_stat_card(title, card_id, icon, color):
    """Create a statistics card"""
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
    """Create a graph card"""
    return dbc.Card([
        dbc.CardHeader(html.H5(title, style={'color': COLORS['text']})),
        dbc.CardBody([
            dcc.Graph(id=graph_id, style={'height': '300px'})
        ])
    ], style={'backgroundColor': COLORS['card_bg'], 'border': f'1px solid {COLORS["accent"]}'})


def create_table_card(title, table_id):
    """Create a table card"""
    return dbc.Card([
        dbc.CardHeader(html.H5(title, style={'color': COLORS['text']})),
        dbc.CardBody([
            html.Div(id=table_id, style={'maxHeight': '300px', 'overflowY': 'auto'})
        ])
    ], style={'backgroundColor': COLORS['card_bg'], 'border': f'1px solid {COLORS["accent"]}'})


def create_empty_figure(message):
    """Create empty figure with message"""
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
        showarrow=False,
        font=dict(size=16, color=COLORS['text'])
    )
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor=COLORS['card_bg'],
        plot_bgcolor=COLORS['card_bg'],
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        margin=dict(l=40, r=40, t=40, b=40)
    )
    return fig


# Initialize traffic capture with callback
def detection_callback(features_df, flow_id, packet_info):
    """Callback when features are extracted"""
    detector.predict(features_df, flow_id, packet_info)


# Use 'lo' - traffic_capture.py will auto-detect Windows loopback
capture = TrafficCapture(interface='lo', callback=detection_callback)

# Initialize Dash app
app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.CYBORG,
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
    ],
    suppress_callback_exceptions=True
)

# Layout - NOW FUNCTIONS ARE DEFINED
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H1([
                    html.I(className="fas fa-shield-alt me-3"),
                    "DDoS Detection System - SOC Dashboard"
                ], style={
                    'color': COLORS['accent'],
                    'textAlign': 'center',
                    'fontWeight': 'bold',
                    'marginBottom': '10px'
                }),
                html.P("Real-time Network Traffic Analysis & Threat Detection",
                       style={'textAlign': 'center', 'color': COLORS['text'], 'opacity': '0.8'})
            ])
        ], width=12)
    ], className='mb-4 mt-3'),
    
    # Control buttons
    dbc.Row([
        dbc.Col([
            dbc.ButtonGroup([
                dbc.Button([html.I(className="fas fa-play me-2"), "Start Capture"],
                          id='start-btn', color='success', n_clicks=0),
                dbc.Button([html.I(className="fas fa-stop me-2"), "Stop Capture"],
                          id='stop-btn', color='danger', n_clicks=0),
                dbc.Button([html.I(className="fas fa-redo me-2"), "Reset Stats"],
                          id='reset-btn', color='warning', n_clicks=0),
            ])
        ], width=12, className='text-center mb-4')
    ]),
    
    html.Div(id='status-message', className='mb-3'),
    
    # Stats cards
    dbc.Row([
        dbc.Col([
            create_stat_card("Total Packets", "total-packets", "fas fa-network-wired", COLORS['accent']),
        ], width=3),
        dbc.Col([
            create_stat_card("Active Flows", "active-flows", "fas fa-stream", COLORS['warning']),
        ], width=3),
        dbc.Col([
            create_stat_card("Benign Traffic", "benign-count", "fas fa-check-circle", COLORS['success']),
        ], width=3),
        dbc.Col([
            create_stat_card("DDoS Detected", "ddos-count", "fas fa-exclamation-triangle", COLORS['danger']),
        ], width=3),
    ], className='mb-4'),
    
    # Detection rate and packets per second
    dbc.Row([
        dbc.Col([
            create_stat_card("Detection Rate", "detection-rate", "fas fa-percentage", COLORS['warning']),
        ], width=6),
        dbc.Col([
            create_stat_card("Packets/Second", "packets-per-sec", "fas fa-tachometer-alt", COLORS['accent']),
        ], width=6),
    ], className='mb-4'),
    
    # Graphs
    dbc.Row([
        dbc.Col([
            create_graph_card("Real-time Detection Timeline", 'detection-timeline')
        ], width=8),
        dbc.Col([
            create_graph_card("Traffic Distribution", 'traffic-distribution')
        ], width=4),
    ], className='mb-4'),
    
    # Active threats and recent detections
    dbc.Row([
        dbc.Col([
            create_table_card("Active Threats", 'active-threats-table')
        ], width=6),
        dbc.Col([
            create_table_card("Recent Detections", 'recent-detections-table')
        ], width=6),
    ], className='mb-4'),
    
    # Recent packets
    dbc.Row([
        dbc.Col([
            create_table_card("Recent Network Packets", 'recent-packets-table')
        ], width=12),
    ], className='mb-4'),
    
    # Update interval
    dcc.Interval(id='interval-component', interval=1000, n_intervals=0),
    
], fluid=True, style={'backgroundColor': COLORS['background'], 'minHeight': '100vh', 'padding': '20px'})


# Callbacks
@app.callback(
    Output('status-message', 'children'),
    [Input('start-btn', 'n_clicks'),
     Input('stop-btn', 'n_clicks'),
     Input('reset-btn', 'n_clicks')],
    prevent_initial_call=True
)
def control_capture(start_clicks, stop_clicks, reset_clicks):
    """Control traffic capture"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return ""
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'start-btn':
        if not capture.running:
            capture.start()
            return dbc.Alert("Traffic capture started!", color="success", duration=3000)
        return dbc.Alert("Capture already running!", color="warning", duration=3000)
    
    elif button_id == 'stop-btn':
        if capture.running:
            capture.stop()
            return dbc.Alert("Traffic capture stopped!", color="info", duration=3000)
        return dbc.Alert("Capture not running!", color="warning", duration=3000)
    
    elif button_id == 'reset-btn':
        detector.reset_stats()
        return dbc.Alert("Statistics reset!", color="info", duration=3000)
    
    return ""


@app.callback(
    [Output('total-packets', 'children'),
     Output('active-flows', 'children'),
     Output('benign-count', 'children'),
     Output('ddos-count', 'children'),
     Output('detection-rate', 'children'),
     Output('packets-per-sec', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_stats(n):
    """Update statistics cards"""
    capture_stats = capture.get_stats()
    detector_stats = detector.get_stats()
    
    return (
        f"{capture_stats['total_packets']:,}",
        f"{capture_stats['total_flows']:,}",
        f"{detector_stats['benign_count']:,}",
        f"{detector_stats['ddos_count']:,}",
        f"{detector_stats['detection_rate']*100:.1f}%",
        f"{capture_stats['packets_per_second']:,}"
    )


@app.callback(
    Output('detection-timeline', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_timeline(n):
    """Update detection timeline graph"""
    timeline_data = detector.get_timeline_data(minutes=5)
    
    if not timeline_data:
        return create_empty_figure("Waiting for data...")
    
    # Separate benign and DDoS
    timestamps_benign = []
    timestamps_ddos = []
    probs_benign = []
    probs_ddos = []
    
    for item in timeline_data:
        ts = datetime.fromisoformat(item['timestamp'])
        if item['type'] == 'Benign':
            timestamps_benign.append(ts)
            probs_benign.append(item['probability'])
        else:
            timestamps_ddos.append(ts)
            probs_ddos.append(item['probability'])
    
    fig = go.Figure()
    
    if timestamps_benign:
        fig.add_trace(go.Scatter(
            x=timestamps_benign,
            y=probs_benign,
            mode='markers',
            name='Benign',
            marker=dict(color=COLORS['benign'], size=8),
        ))
    
    if timestamps_ddos:
        fig.add_trace(go.Scatter(
            x=timestamps_ddos,
            y=probs_ddos,
            mode='markers',
            name='DDoS Attack',
            marker=dict(color=COLORS['ddos'], size=10, symbol='x'),
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor=COLORS['card_bg'],
        plot_bgcolor=COLORS['card_bg'],
        font=dict(color=COLORS['text']),
        xaxis_title="Time",
        yaxis_title="DDoS Probability",
        hovermode='closest',
        showlegend=True,
        margin=dict(l=40, r=40, t=40, b=40),
        yaxis=dict(range=[0, 1])
    )
    
    return fig


@app.callback(
    Output('traffic-distribution', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_distribution(n):
    """Update traffic distribution pie chart"""
    stats = detector.get_stats()
    
    benign = stats['benign_count']
    ddos = stats['ddos_count']
    
    if benign == 0 and ddos == 0:
        return create_empty_figure("No data yet")
    
    fig = go.Figure(data=[go.Pie(
        labels=['Benign', 'DDoS'],
        values=[benign, ddos],
        marker=dict(colors=[COLORS['benign'], COLORS['ddos']]),
        hole=0.4,
        textinfo='label+percent',
        textfont=dict(size=14, color='white')
    )])
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor=COLORS['card_bg'],
        plot_bgcolor=COLORS['card_bg'],
        font=dict(color=COLORS['text']),
        showlegend=True,
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    return fig


@app.callback(
    Output('active-threats-table', 'children'),
    [Input('interval-component', 'n_intervals')]
)
def update_threats_table(n):
    """Update active threats table"""
    threats = detector.get_active_threats()
    
    if not threats:
        return html.P("No active threats detected", 
                     style={'textAlign': 'center', 'color': COLORS['success'], 'padding': '20px'})
    
    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    threats = sorted(threats, key=lambda x: severity_order.get(x['severity'], 4))
    
    table_header = [
        html.Thead(html.Tr([
            html.Th("Source IP"),
            html.Th("Count"),
            html.Th("Probability"),
            html.Th("Severity"),
        ]))
    ]
    
    rows = []
    for threat in threats[:10]:  # Show top 10
        severity_color = {
            'critical': COLORS['danger'],
            'high': COLORS['warning'],
            'medium': COLORS['accent'],
            'low': COLORS['text']
        }.get(threat['severity'], COLORS['text'])
        
        rows.append(html.Tr([
            html.Td(threat['src_ip']),
            html.Td(threat['count']),
            html.Td(f"{threat['max_probability']*100:.1f}%"),
            html.Td(threat['severity'].upper(), style={'color': severity_color, 'fontWeight': 'bold'}),
        ]))
    
    table_body = [html.Tbody(rows)]
    
    return dbc.Table(
        table_header + table_body,
        bordered=True,
        dark=True,
        hover=True,
        responsive=True,
        striped=True,
        style={'fontSize': '0.9rem'}
    )


@app.callback(
    Output('recent-detections-table', 'children'),
    [Input('interval-component', 'n_intervals')]
)
def update_detections_table(n):
    """Update recent detections table"""
    detections = detector.get_recent_detections(10)
    
    if not detections:
        return html.P("No detections yet", 
                     style={'textAlign': 'center', 'color': COLORS['text'], 'padding': '20px'})
    
    table_header = [
        html.Thead(html.Tr([
            html.Th("Time"),
            html.Th("Type"),
            html.Th("Probability"),
            html.Th("Source"),
        ]))
    ]
    
    rows = []
    for det in reversed(detections):  # Most recent first
        time_str = datetime.fromisoformat(det['timestamp']).strftime('%H:%M:%S')
        type_color = COLORS['ddos'] if det['prediction'] == 1 else COLORS['benign']
        
        rows.append(html.Tr([
            html.Td(time_str),
            html.Td(det['prediction_label'], style={'color': type_color, 'fontWeight': 'bold'}),
            html.Td(f"{det['probability']*100:.1f}%"),
            html.Td(det['src_ip'], style={'fontSize': '0.85rem'}),
        ]))
    
    table_body = [html.Tbody(rows)]
    
    return dbc.Table(
        table_header + table_body,
        bordered=True,
        dark=True,
        hover=True,
        responsive=True,
        striped=True,
        style={'fontSize': '0.9rem'}
    )


@app.callback(
    Output('recent-packets-table', 'children'),
    [Input('interval-component', 'n_intervals')]
)
def update_packets_table(n):
    """Update recent packets table"""
    packets = capture.get_recent_packets(15)
    
    if not packets:
        return html.P("No packets captured yet", 
                     style={'textAlign': 'center', 'color': COLORS['text'], 'padding': '20px'})
    
    table_header = [
        html.Thead(html.Tr([
            html.Th("Time"),
            html.Th("Source IP"),
            html.Th("Destination IP"),
            html.Th("Protocol"),
            html.Th("Length"),
        ]))
    ]
    
    rows = []
    for pkt in reversed(packets):  # Most recent first
        time_str = datetime.fromisoformat(pkt['timestamp']).strftime('%H:%M:%S.%f')[:-3]
        
        rows.append(html.Tr([
            html.Td(time_str, style={'fontSize': '0.85rem'}),
            html.Td(pkt['src_ip'], style={'fontSize': '0.85rem'}),
            html.Td(pkt['dst_ip'], style={'fontSize': '0.85rem'}),
            html.Td(pkt['protocol']),
            html.Td(f"{pkt['length']} bytes"),
        ]))
    
    table_body = [html.Tbody(rows)]
    
    return dbc.Table(
        table_header + table_body,
        bordered=True,
        dark=True,
        hover=True,
        responsive=True,
        striped=True,
        style={'fontSize': '0.9rem'}
    )


if __name__ == '__main__':
    print("\n" + "="*60)
    print("DDoS Detection System - SOC Dashboard")
    print("="*60)
    print("\nStarting dashboard server...")
    print("Dashboard will be available at: http://127.0.0.1:8050")
    print("\nPress CTRL+C to stop the server")
    print("="*60 + "\n")
    
    app.run(debug=False, host='127.0.0.1', port=8050)