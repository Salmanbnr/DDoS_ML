import platform
import os
import dash
from dash import dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from datetime import datetime, timedelta
import threading
import time
import traceback

# --- Delay importing heavy capture/detector until after we choose interface ---
try:
    # Try to import detector first (so errors are obvious)
    from ddos_detector import DDoSDetector
except Exception as e:
    print("Error importing ddos_detector. Make sure ddos_detector.py exists and is valid.")
    raise

# Determine interface heuristically (Windows friendly)
# If you want to force an interface, replace None with the string shown by find_interface.py
# e.g. INTERFACE = r'\Device\NPF_{DFC698EF-2612-46C7-BF80-ACBA4C9EE6B3}'
INTERFACE = None

if platform.system() == "Windows":
    # Prefer the named loopback device if available
    # Common Npcap loopback name: '\\Device\\NPF_Loopback' (or r'\Device\NPF_Loopback')
    try_names = [r'\Device\NPF_Loopback', r'\\Device\\NPF_Loopback']
    # You may override by setting environment variable INTERFACE
    env_if = os.getenv("DDOS_IF")
    if env_if:
        INTERFACE = env_if
    else:
        # Try the loopback names, otherwise leave None to capture all interfaces (works on many Windows setups)
        INTERFACE = None
        for n in try_names:
            try:
                # We don't test sniff here; just prefer the name
                INTERFACE = n
                break
            except:
                INTERFACE = None

# Now import TrafficCapture (after interface selection to avoid early circulars)
try:
    from traffic_capture import TrafficCapture
except Exception as e:
    print("Error importing TrafficCapture from traffic_capture.py.")
    print("Make sure traffic_capture.py doesn't accidentally import dashboard or itself.")
    print("Traceback:")
    traceback.print_exc()
    raise

# --- Initialize the detector with practical defaults for local testing ---
# Lower threshold and small smoothing window tend to work better for short local simulated flows.
detector = DDoSDetector(
    model_path='model/best_model.pkl',
    scaler_path='model/scaler.pkl',
    alert_threshold=0.6,    # more sensitive for testing; raise to reduce false positives
    smoothing_window=3,     # short smoothing (number of recent probs to average)
    min_history_for_detection=1
)

# Colors & helpers (kept same as your UI)
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
    fig.add_annotation(text=message, xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
                       font=dict(size=16, color=COLORS['text']))
    fig.update_layout(template='plotly_dark', paper_bgcolor=COLORS['card_bg'],
                      plot_bgcolor=COLORS['card_bg'],
                      xaxis=dict(visible=False), yaxis=dict(visible=False),
                      margin=dict(l=40, r=40, t=40, b=40))
    return fig

# --- Detection callback: send feature DF to detector and log result ---
def detection_callback(features_df, flow_id, packet_info):
    try:
        result = detector.predict(features_df, flow_id, packet_info)
        if result:
            # Print diagnostics so you can see probabilities in terminal
            inst = result.get('instant_probability', None)
            prob = result.get('probability', result.get('instant_probability'))
            label = result.get('prediction_label', 'Unknown')
            src = result.get('src_ip')
            dst = result.get('dst_ip')
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Flow {flow_id} {src}->{dst} instant={inst:.3f} smoothed={prob:.3f} label={label}")
            # If DDoS, print a clear alert
            if result.get('prediction') == 1:
                print(">>> ALERT: DDoS detected:", src, "->", dst, f"prob={prob:.3f}")
    except Exception as e:
        print("Error in detection_callback:", e)
        traceback.print_exc()

# Create TrafficCapture instance with chosen interface
print(f"Using interface: {INTERFACE!r} (None means capture on all interfaces). If this is wrong, set env DDOS_IF or edit dashboard.py)")
capture = TrafficCapture(interface=INTERFACE, callback=detection_callback)

# --- Dash app (UI kept mostly same, timeline now shows real points) ---
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
                html.H1([html.I(className="fas fa-shield-alt me-3"), "DDoS Detection System - SOC Dashboard"],
                        style={'color': COLORS['accent'], 'textAlign': 'center', 'fontWeight': 'bold', 'marginBottom': '10px'}),
                html.P("Real-time Network Traffic Analysis & Threat Detection",
                       style={'textAlign': 'center', 'color': COLORS['text'], 'opacity': '0.8'})
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

# --- Callbacks (control capture) ---
@app.callback(
    Output('status-message', 'children'),
    [Input('start-btn', 'n_clicks'), Input('stop-btn', 'n_clicks'), Input('reset-btn', 'n_clicks')],
    prevent_initial_call=True
)
def control_capture(start, stop, reset):
    ctx = dash.callback_context
    if not ctx.triggered:
        return ""
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == 'start-btn':
        if not capture.running:
            try:
                capture.start()
                return dbc.Alert("Capture started!", color="success", duration=3000)
            except Exception as e:
                print("Failed to start capture:", e)
                traceback.print_exc()
                return dbc.Alert(f"Failed to start capture: {e}", color="danger", duration=5000)
    elif button_id == 'stop-btn':
        if capture.running:
            capture.stop()
            return dbc.Alert("Capture stopped!", color="info", duration=3000)
    elif button_id == 'reset-btn':
        detector.reset_stats()
        return dbc.Alert("Statistics reset!", color="info", duration=3000)
    return ""

# --- Stats updater ---
@app.callback(
    [Output('total-packets', 'children'), Output('active-flows', 'children'), Output('benign-count', 'children'),
     Output('ddos-count', 'children'), Output('detection-rate', 'children'), Output('packets-per-sec', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_stats(n):
    try:
        c_stats = capture.get_stats()
        d_stats = detector.get_stats()
        return f"{c_stats['total_packets']:,}", f"{c_stats['total_flows']:,}", f"{d_stats['benign_count']:,}", f"{d_stats['ddos_count']:,}", f"{d_stats['detection_rate']*100:.1f}%", f"{c_stats.get('packets_per_second', 0):,}"
    except Exception as e:
        print("Error in update_stats:", e)
        return "0", "0", "0", "0", "0%", "0"

# --- Timeline plot (shows instant & smoothed probabilities over time) ---
@app.callback(Output('detection-timeline', 'figure'), [Input('interval-component', 'n_intervals')])
def update_timeline(n):
    try:
        timeline_data = detector.get_timeline_data(minutes=10)
        if not timeline_data:
            return create_empty_figure("Waiting for data...")

        # Build scatter points
        times = [datetime.fromisoformat(d['timestamp']) for d in timeline_data]
        probs = [d['probability'] for d in timeline_data]
        labels = [d['type'] for d in timeline_data]

        df_points = {
            'time': times,
            'prob': probs,
            'label': labels
        }

        fig = go.Figure()
        # Scatter for benign
        fig.add_trace(go.Scatter(
            x=[t for t, l in zip(times, labels) if l == 'Benign'],
            y=[p for p, l in zip(probs, labels) if l == 'Benign'],
            mode='markers+lines',
            name='Benign',
            marker=dict(size=6),
            line=dict(width=1),
        ))
        # Scatter for ddos
        fig.add_trace(go.Scatter(
            x=[t for t, l in zip(times, labels) if l == 'DDoS'],
            y=[p for p, l in zip(probs, labels) if l == 'DDoS'],
            mode='markers+lines',
            name='DDoS',
            marker=dict(size=8),
            line=dict(width=1),
        ))

        fig.update_layout(template='plotly_dark', paper_bgcolor=COLORS['card_bg'], plot_bgcolor=COLORS['card_bg'],
                          margin=dict(l=40, r=40, t=40, b=40),
                          yaxis=dict(range=[0, 1], title='Probability'),
                          xaxis=dict(title='Time'))
        return fig
    except Exception as e:
        print("Error building timeline:", e)
        traceback.print_exc()
        return create_empty_figure("Error building timeline")

@app.callback(Output('traffic-distribution', 'figure'), [Input('interval-component', 'n_intervals')])
def update_distribution(n):
    try:
        stats = detector.get_stats()
        if stats['benign_count'] == 0 and stats['ddos_count'] == 0:
            return create_empty_figure("No data")
        fig = go.Figure(data=[
            go.Pie(labels=['Benign', 'DDoS'], values=[stats['benign_count'], stats['ddos_count']],
                   marker=dict(colors=[COLORS['benign'], COLORS['ddos']]), hole=0.4)
        ])
        fig.update_layout(template='plotly_dark', paper_bgcolor=COLORS['card_bg'], plot_bgcolor=COLORS['card_bg'],
                          margin=dict(l=20, r=20, t=20, b=20))
        return fig
    except Exception as e:
        print("Error in update_distribution:", e)
        return create_empty_figure("Error")

@app.callback(Output('active-threats-table', 'children'), [Input('interval-component', 'n_intervals')])
def update_threats_table(n):
    threats = detector.get_active_threats()
    if not threats:
        return html.P("No threats", style={'textAlign': 'center', 'color': COLORS['success']})

    table_header = [html.Thead(html.Tr([html.Th("Source IP"), html.Th("Count"), html.Th("Probability"), html.Th("Severity")]))]
    rows = [html.Tr([html.Td(t['src_ip']), html.Td(t['count']), html.Td(f"{t['max_probability']*100:.1f}%"), html.Td(t['severity'].upper())]) for t in threats[:10]]

    return dbc.Table(table_header + [html.Tbody(rows)], bordered=True, color='dark', hover=True, responsive=True, striped=True, style={'fontSize': '0.9rem'})

@app.callback(Output('recent-detections-table', 'children'), [Input('interval-component', 'n_intervals')])
def update_detections_table(n):
    detections = detector.get_recent_detections(50)
    if not detections:
        return html.P("No detections yet")

    table_header = [html.Thead(html.Tr([html.Th("Time"), html.Th("Type"), html.Th("Probability"), html.Th("Source")]))]
    rows = [html.Tr([html.Td(datetime.fromisoformat(d['timestamp']).strftime('%H:%M:%S')), html.Td(d['prediction_label']), html.Td(f"{d['probability']*100:.1f}%"), html.Td(d['src_ip'])]) for d in reversed(detections)]

    return dbc.Table(table_header + [html.Tbody(rows)], bordered=True, color='dark', hover=True, responsive=True, striped=True, style={'fontSize': '0.9rem'})

@app.callback(Output('recent-packets-table', 'children'), [Input('interval-component', 'n_intervals')])
def update_packets_table(n):
    packets = capture.get_recent_packets(15)
    if not packets:
        return html.P("No packets captured")

    table_header = [html.Thead(html.Tr([html.Th("Time"), html.Th("Src"), html.Th("Dst"), html.Th("Prot"), html.Th("Len")]))]
    rows = [html.Tr([html.Td(datetime.fromisoformat(p['timestamp']).strftime('%H:%M:%S')), html.Td(p['src_ip']), html.Td(p['dst_ip']), html.Td(p['protocol']), html.Td(f"{p['length']}B")]) for p in reversed(packets)]

    return dbc.Table(table_header + [html.Tbody(rows)], bordered=True, color='dark', hover=True, responsive=True, striped=True, style={'fontSize': '0.9rem'})

# Run server
if __name__ == '__main__':
    print("Starting Dashboard on http://127.0.0.1:8050")
    app.run(debug=False, host='127.0.0.1', port=8050)
