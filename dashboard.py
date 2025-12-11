import platform
import os
import dash
from dash import dcc, html, Input, Output
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from datetime import datetime
import threading
import time
import traceback
import logging

# --- CRITICAL IMPORTS ---
# Ensure these imports are successful
try:
    # Assuming ddos_detector.py is in the same directory and is functional
    from ddos_detector import DDoSDetector
    # Import sniff and IP from scapy for packet capture
    from scapy.all import sniff, IP 
except ImportError as e:
    logging.critical(f"CRITICAL ERROR: Failed to import required modules. Detail: {e}")
    # Set to None if imports fail to prevent later crashes
    DDoSDetector = None
    sniff = None


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')  # Set to DEBUG for detailed logs

# --- CONFIGURATION ---
# FORCE to None to capture on ALL interfaces (critical for Windows/Docker)
INTERFACE = None
logging.info("INTERFACE forced to None - capturing on all available interfaces to ensure Docker traffic is seen.")
    
# Global detector instance
detector = None
capture_thread = None
capture_status = "Not Running"
MIN_PACKETS_FOR_PREDICTION = 2
if DDoSDetector:
    try:
        # Assumes model files are in 'model/'
        detector = DDoSDetector()
        logging.info("Successfully loaded model and scaler.")
    except FileNotFoundError:
        logging.critical("CRITICAL: Model files not found. Please create a 'model/' folder and place 'best_model.pkl' and 'scaler.pkl' inside it.")
    except Exception as e:
        logging.critical(f"Failed to initialize DDoSDetector: {e}")


# --- PACKET PROCESSING FUNCTIONS ---

def packet_callback(packet):
    """Called by scapy's sniff() for every captured packet."""
    if detector is None:
        return

    logging.debug(f"Packet captured: SRC={packet[IP].src if IP in packet else 'N/A'}, DST={packet[IP].dst if IP in packet else 'N/A'}, Summary={packet.summary()}")  # Log every packet

    if IP in packet:
        try:
            # Extract features from the packet/flow
            features_df, flow_id, packet_info = detector.extractor.process_packet(packet)
            
            if features_df is not None and not features_df.empty:
                # Predict only if enough packets have been seen (features_df is not None)
                result = detector.predict(features_df, flow_id, packet_info)
                
                if result['is_ddos']:
                    logging.warning(f"🚨 DDoS Alert: {result['flow_id']} | Confidence: {result['confidence']:.2f}")

        except Exception as e:
            # Handle exceptions during feature extraction or prediction gracefully
            # Note: The detector already logs non-finite value warnings internally.
            logging.error(f"Error processing packet: {e}")
            logging.error(traceback.format_exc())


def start_capture(interface, bpf_filter="ip"):
    """
    Starts the Scapy packet capture in a dedicated thread.
    """
    global capture_status
    if sniff is None:
        logging.error("Scapy library not initialized, cannot start capture.")
        capture_status = "Error (Scapy Missing)"
        return
    
    logging.info(f"Starting packet capture on interface: {interface or 'ALL'} with filter: '{bpf_filter}'")
    capture_status = "Running"
    
    try:
        # Sniff is a blocking call. 
        sniff(iface=interface, 
              filter=bpf_filter, 
              prn=packet_callback, 
              store=0) 
    except Exception as e:
        logging.error(f"Scapy sniff failed. Check permissions (run as admin). Detail: {e}")
        logging.error(traceback.format_exc())
        capture_status = f"Error: {e.__class__.__name__}"


def start_detection_thread():
    """Manages the lifecycle of the packet capture thread."""
    global capture_thread, capture_status
    if detector is None or sniff is None:
        capture_status = "Error (Init Failure)"
        return
    
    if capture_thread is None or not capture_thread.is_alive():
        # Daemon thread ensures the thread terminates when the main process exits
        capture_thread = threading.Thread(target=start_capture, args=(INTERFACE,), daemon=True) 
        capture_thread.start()
        logging.info("Detection thread started successfully.")
    else:
        logging.info("Detection thread is already running.")


# Start the detection thread immediately upon script execution if detector initialized
if detector:
    start_detection_thread()
else:
    capture_status = "Initialization Failed"

# --- DASHBOARD LAYOUT AND CALLBACKS ---
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY], title="DDoS Detection Dashboard")
# Suppress Dash callback warnings for elements that are generated dynamically (like the table)
app.config.suppress_callback_exceptions = True 

def stat_card(id_name, title, color):
    """Utility function for creating a statistics card."""
    return dbc.Card(
        dbc.CardBody([
            html.H5(title, className="card-title"),
            # Ensure the ID here matches the callback OUTPUT ID
            html.P(id=id_name, className="card-text", style={'fontSize': '24px', 'color': color}), 
        ]),
        className="text-center m-1",
        color="secondary", 
        inverse=True,
        style={"border-left": f"5px solid {color}"}
    )

app.layout = dbc.Container([
    html.H1("Real-Time DDoS Monitoring System", className="text-center my-3 text-info"),
    
    # Interval component triggers the dashboard updates every 1 second
    dcc.Interval(id='interval-component', interval=1*1000, n_intervals=0), 

    dbc.Row([
        # STATS CARD IDs
        dbc.Col(stat_card('status-pps', "Packets/s (All)", "cyan"), md=3),
        dbc.Col(stat_card('status-predictions', "Total Flow Predictions", "light"), md=3),
        dbc.Col(stat_card('status-ddos-count', "Total DDoS Detections", "danger"), md=3),
        dbc.Col(stat_card('status-alert', "System Status", "warning"), md=3),
    ], className="mb-4"),

    dbc.Row([
        # GRAPH IDs
        dbc.Col(dcc.Graph(id='graph-traffic-rate', config={'displayModeBar': False}), md=6), 
        dbc.Col(dcc.Graph(id='graph-detection-timeline', config={'displayModeBar': False}), md=6), 
    ], className="mb-4"),

    dbc.Row([
        dbc.Col(html.Div([
            html.H4("Recent Detections", className="text-info"),
            # TABLE ID
            html.Div(id='table-recent-detections', className="table-responsive") 
        ]), md=12)
    ])
], fluid=True)


# --- CALLBACKS ---

# Callback 1: Updates status cards
@app.callback(
    [
        Output('status-pps', 'children'),
        Output('status-predictions', 'children'),
        Output('status-ddos-count', 'children'),
        Output('status-alert', 'children'),
        Output('status-alert', 'style'),
    ],
    [Input('interval-component', 'n_intervals')]
)
def update_stats(n):
    """Updates the status cards with the latest detector stats."""
    if detector is None:
        # If detector initialization failed
        return "N/A", "N/A", "N/A", capture_status, {'fontSize': '24px', 'color': 'red', 'fontWeight': 'bold'}
        
    stats = detector.get_stats()
    
    pps = f"{stats['packets_per_second']:.2f}"
    predictions = stats['total_predictions']
    ddos_count = stats['ddos_count']
    
    # Logic for overall alert status
    alert_rate_threshold_high = 0.3 
    alert_rate_threshold_elevated = 0.1

    timeline_data = detector.get_timeline_data()
    current_ddos_rate = 0
    if timeline_data and 'rate' in timeline_data[-1]:
        current_ddos_rate = timeline_data[-1]['rate']
    
    # Determine alert status
    if current_ddos_rate > alert_rate_threshold_high:
        alert_status = "⚠️ HIGH THREAT"
        status_color = 'red'
    elif current_ddos_rate > alert_rate_threshold_elevated:
        alert_status = "🟠 ELEVATED"
        status_color = 'orange'
    else:
        alert_status = "🟢 NORMAL"
        status_color = 'green'
        
    status_style = {'fontSize': '24px', 'color': status_color, 'fontWeight': 'bold'}
    
    logging.debug(f"Stats update: PPS={pps}, Predictions={predictions}, DDoS={ddos_count}, Status={alert_status}")  # Added debug
    return pps, predictions, ddos_count, alert_status, status_style

# Callback 2: Updates Traffic Rate Graph
@app.callback(
    Output('graph-traffic-rate', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_traffic_graph(n):
    """Updates the traffic rate graph."""
    if detector is None:
        return go.Figure()
        
    timeline_data = detector.get_timeline_data()
    # Limit data for performance and clarity
    data_points = timeline_data[-300:] 
    
    times = [datetime.fromtimestamp(d['time']) for d in data_points]
    pps_data = [d['total_pps'] for d in data_points]
    
    fig = go.Figure(data=[
        go.Scatter(x=times, y=pps_data, mode='lines', line=dict(color='cyan'), name='Total PPS', fill='tozeroy')
    ])
    
    fig.update_layout(
        title='Live Packet Traffic Rate (Packets/s)',
        xaxis_title='Time',
        yaxis_title='Packets/s',
        template='plotly_dark',
        height=350,
        margin={'t': 50, 'b': 30, 'l': 50, 'r': 10}
    )
    return fig

# Callback 3: Updates Detection Timeline Graph
@app.callback(
    Output('graph-detection-timeline', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_detection_graph(n):
    """Updates the DDoS detection rate graph."""
    if detector is None:
        return go.Figure()
        
    timeline_data = detector.get_timeline_data()
    data_points = timeline_data[-300:] 

    times = [datetime.fromtimestamp(d['time']) for d in data_points]
    ddos_rate = [d['rate'] for d in data_points]
    
    fig = go.Figure(data=[
        go.Bar(x=times, y=ddos_rate, marker=dict(color='red'), name='DDoS Rate (Events/s)')
    ])
    
    fig.update_layout(
        title='DDoS Detection Rate',
        xaxis_title='Time',
        yaxis_title='DDoS Events per Second',
        template='plotly_dark',
        height=350,
        margin={'t': 50, 'b': 30, 'l': 50, 'r': 10}
    )
    return fig

# Callback 4: Updates Recent Detections Table
@app.callback(
    Output('table-recent-detections', 'children'),
    [Input('interval-component', 'n_intervals')]
)
def update_detections_table(n):
    """Updates the table of recent detections."""
    if detector is None:
        return dbc.Alert(f"Detector failed to initialize. Current status: {capture_status}. Check console for error messages.", color="danger")

    recent_detections = detector.get_recent_detections(n=10)
    
    if not recent_detections:
        return dbc.Alert("No detections yet. Monitoring traffic...", color="secondary")
        
    table_header = [
        html.Thead(html.Tr([
            html.Th("Time"), html.Th("Source IP"), html.Th("Flow ID"), html.Th("Status"), html.Th("Confidence")
        ]))
    ]
    
    rows = []
    for d in recent_detections:
        is_ddos_text = "🚨 DDoS" if d['is_ddos'] else "✅ Benign"
        color = 'red' if d['is_ddos'] else 'green'
        
        rows.append(html.Tr([
            html.Td(datetime.fromtimestamp(d['time']).strftime('%H:%M:%S')),
            html.Td(d['src_ip']),
            html.Td(d['flow_id']),
            html.Td(is_ddos_text, style={'color': color, 'fontWeight': 'bold'}),
            html.Td(f"{d['confidence']:.4f}"),
        ]))

    table_body = [html.Tbody(rows)]
    
    # FIX APPLIED HERE: Replaced 'dark=True' with 'color="dark"'
    return dbc.Table(table_header + table_body, striped=True, bordered=True, hover=True, color='dark')


if __name__ == '__main__':
    if detector is None:
         logging.critical("Dashboard startup failed. Please resolve model/scaler path or import issues.")
    else:
        try:
            logging.info("Dashboard starting. Access at http://127.0.0.1:8050/")
            app.run(debug=False, host='0.0.0.0') 
        except Exception as e:
            logging.error(f"Failed to run Dash server: {e}")