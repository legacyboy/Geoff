import streamlit as st
import pandas as pd
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzer import OnboardingAnalyzer
import plotly.graph_objects as go
import plotly.express as px

# Page config
st.set_page_config(
    page_title="Onboarding Drop-off Analyzer",
    page_icon="📊",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1.5rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    .critical-alert {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        margin: 1rem 0;
    }
    .success-alert {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

def create_funnel_chart(funnel_steps):
    """Create a funnel visualization"""
    steps = [step.name.replace('_', ' ').title() for step in funnel_steps]
    users = [step.users_entered for step in funnel_steps]
    
    fig = go.Figure(go.Funnel(
        y=steps,
        x=users,
        textposition="inside",
        textinfo="value+percent initial",
        opacity=0.65,
        marker={
            "color": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b"],
            "line": {"width": [2, 2, 2, 3, 2, 2], "color": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b"]}
        },
        connector={"line": {"color": "white", "dash": "dot"}}
    ))
    
    fig.update_layout(
        title="Onboarding Funnel",
        font_size=12,
        height=500
    )
    
    return fig

def create_conversion_chart(funnel_steps):
    """Create a bar chart of conversion rates"""
    steps = [step.name.replace('_', ' ').title() for step in funnel_steps]
    rates = [step.conversion_rate * 100 for step in funnel_steps]
    
    colors = ['#4caf50' if r >= 70 else '#ff9800' if r >= 50 else '#f44336' for r in rates]
    
    fig = go.Figure(data=[
        go.Bar(
            x=steps,
            y=rates,
            marker_color=colors,
            text=[f"{r:.1f}%" for r in rates],
            textposition='auto',
        )
    ])
    
    fig.update_layout(
        title="Step Conversion Rates",
        yaxis_title="Conversion Rate (%)",
        yaxis_range=[0, 105],
        height=400
    )
    
    # Add threshold line at 70%
    fig.add_hline(y=70, line_dash="dash", line_color="red", 
                  annotation_text="70% threshold")
    
    return fig

def main():
    # Header
    st.markdown('<p class="main-header">📊 Onboarding Drop-off Analyzer</p>', 
                unsafe_allow_html=True)
    st.markdown("AI-powered analysis of your user onboarding funnel")
    
    # Sidebar
    st.sidebar.header("Configuration")
    
    st.sidebar.subheader("1. Data Source")
    data_source = st.sidebar.radio(
        "Choose data source:",
        ["Upload CSV", "Use Sample Data"]
    )
    
    st.sidebar.subheader("2. Analysis Settings")
    conversion_threshold = st.sidebar.slider(
        "Critical Drop-off Threshold (%)",
        min_value=30, max_value=90, value=70
    ) / 100
    
    min_dropoffs = st.sidebar.number_input(
        "Minimum Drop-offs to Flag",
        min_value=1, value=10
    )
    
    st.sidebar.subheader("3. AI Features")
    openai_key = st.sidebar.text_input(
        "OpenAI API Key (optional)",
        type="password",
        help="Required for AI hypothesis generation"
    )
    
    # Main content
    df = None
    
    if data_source == "Upload CSV":
        uploaded_file = st.file_uploader(
            "Upload your funnel data CSV",
            type=['csv'],
            help="Should have columns: user_id, step_name, timestamp"
        )
        
        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)
            st.success(f"Loaded {len(df)} records")
            
            with st.expander("Preview Data"):
                st.dataframe(df.head(10))
    else:
        # Use sample data
        sample_path = os.path.join(os.path.dirname(__file__), '..', 'examples', 'sample_funnel_data.csv')
        if os.path.exists(sample_path):
            df = pd.read_csv(sample_path)
            st.info("Using sample data (20 users, 6 funnel steps)")
        else:
            st.error("Sample data not found")
    
    if df is not None:
        # Custom step order
        st.subheader("Funnel Step Order")
        
        # Auto-detect steps
        detected_steps = df['step_name'].unique().tolist()
        
        step_order = st.multiselect(
            "Order your funnel steps (drag to reorder):",
            options=detected_steps,
            default=detected_steps
        )
        
        col1, col2 = st.columns([1, 3])
        
        with col1:
            if st.button("🚀 Run Analysis", type="primary"):
                with st.spinner("Analyzing funnel..."):
                    # Initialize analyzer
                    analyzer = OnboardingAnalyzer(openai_key if openai_key else None)
                    
                    # Run analysis
                    try:
                        results = analyzer.full_analysis(
                            df,
                            step_order=step_order if step_order else None,
                            generate_ai_insights=bool(openai_key)
                        )
                        
                        # Store results in session state
                        st.session_state['results'] = results
                        st.session_state['threshold'] = conversion_threshold
                        st.session_state['min_dropoffs'] = min_dropoffs
                        st.success("Analysis complete!")
                    except Exception as e:
                        st.error(f"Error during analysis: {str(e)}")
        
        # Display results if available
        if 'results' in st.session_state:
            results = st.session_state['results']
            
            # Summary metrics
            st.header("📈 Funnel Overview")
            
            if results['funnel_steps']:
                total_entered = results['funnel_steps'][0].users_entered
                total_completed = results['funnel_steps'][-1].users_completed
                overall_conversion = (total_completed / total_entered * 100) if total_entered > 0 else 0
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        "Overall Activation Rate",
                        f"{overall_conversion:.1f}%",
                        help="Percentage of users who completed the entire funnel"
                    )
                
                with col2:
                    st.metric(
                        "Total Users Entered",
                        f"{total_entered:,}"
                    )
                
                with col3:
                    st.metric(
                        "Total Users Activated",
                        f"{total_completed:,}"
                    )
                
                with col4:
                    total_lost = total_entered - total_completed
                    st.metric(
                        "Total Drop-offs",
                        f"{total_lost:,}",
                        delta=f"-{total_lost/total_entered*100:.1f}%" if total_entered > 0 else None,
                        delta_color="inverse"
                    )
            
            # Funnel visualization
            st.plotly_chart(create_funnel_chart(results['funnel_steps']), use_container_width=True)
            
            # Conversion rates
            st.plotly_chart(create_conversion_chart(results['funnel_steps']), use_container_width=True)
            
            # Detailed breakdown
            st.header("🔍 Step-by-Step Breakdown")
            
            for step in results['funnel_steps']:
                with st.expander(f"Step {step.step_number}: {step.name.replace('_', ' ').title()}"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Entered", step.users_entered)
                    with col2:
                        st.metric("Completed", step.users_completed)
                    with col3:
                        st.metric(
                            "Conversion Rate",
                            f"{step.conversion_rate:.1%}",
                            delta=f"{step.conversion_rate*100 - 70:.1f}% vs 70% threshold"
                        )
                    
                    st.metric("Drop-offs", step.dropoff_count)
                    st.metric("Avg Time", f"{step.avg_time_seconds:.0f}s")
            
            # Critical findings
            st.header("🚨 Critical Findings")
            
            # Filter by user settings
            critical = [
                step for step in results['funnel_steps']
                if step.conversion_rate < st.session_state['threshold'] 
                and step.dropoff_count >= st.session_state['min_dropoffs']
            ]
            
            if critical:
                for i, step in enumerate(critical, 1):
                    st.markdown(f"""
                    <div class="critical-alert">
                        <strong>#{i}: Step {step.step_number} "{step.name.replace('_', ' ').title()}"</strong><br>
                        Conversion Rate: <strong>{step.conversion_rate:.1%}</strong> | 
                        Users Lost: <strong>{step.dropoff_count:,}</strong><br>
                        Severity Score: {step.severity_score:.0f} | 
                        Projected Recovery: ~{int(step.dropoff_count * 0.3):,} users (if fixed)
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # AI Hypotheses if available
                    if 'insights' in results:
                        insight = next((ins for ins in results['insights'] if ins['step'].name == step.name), None)
                        if insight and insight['hypotheses']:
                            st.subheader("🤖 AI-Generated Hypotheses")
                            for hyp in insight['hypotheses'][:3]:
                                confidence_emoji = "🔴" if hyp.get('confidence') == 'High' else "🟡" if hyp.get('confidence') == 'Medium' else "🟢"
                                st.markdown(f"""
                                **{confidence_emoji} {hyp.get('confidence', 'N/A')} Confidence**
                                
                                *Hypothesis:* {hyp.get('hypothesis', 'N/A')}
                                
                                *Reasoning:* {hyp.get('reasoning', 'N/A')}
                                
                                *Recommended Experiment:* {hyp.get('experiment', 'N/A')}
                                """)
            else:
                st.markdown("""
                <div class="success-alert">
                    ✅ No critical drop-offs detected! All steps are performing above threshold.
                </div>
                """, unsafe_allow_html=True)
            
            # Full report
            st.header("📄 Full Report")
            with st.expander("View Text Report"):
                st.text(results['report'])
            
            # Export
            st.header("💾 Export")
            if st.download_button(
                label="Download Report (Markdown)",
                data=results['report'],
                file_name="onboarding_analysis_report.md",
                mime="text/markdown"
            ):
                st.success("Report downloaded!")

    # Footer
    st.markdown("---")
    st.markdown("Built with Streamlit • Data never leaves your browser")

if __name__ == "__main__":
    main()
