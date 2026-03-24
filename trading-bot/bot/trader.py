import json
import logging
import os
import time
from datetime import datetime

# Load config
config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.json')
with open(config_path) as f:
    config = json.load(f)

def random_strategy():
    """Random strategy for trading decisions."""
    return 'buy' if (time.time() % 60) < 30 else 'sell'

def generate_report(trade_decision):
    report_time = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'reports')
    report_path = os.path.join(report_dir, f'{report_time}.json')
    
    # Ensure the reports directory exists
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    report_data = {
        'time': report_time,
        'decision': trade_decision
    }
    
    with open(report_path, 'w') as report_file:
        json.dump(report_data, report_file)

def main():
    # Configure logging
    log_path = os.path.join(os.path.dirname(__file__), '..', 'logs', 'trader.log')
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info('Trader started.')
    
    try:
        decision = random_strategy()
        generate_report(decision)
        logging.info(f'Trade Decision: {decision}')
        print(f"Trade executed: {decision}")
        
        # For cron mode, run once and exit
        # For daemon mode, uncomment the loop below
        # while True:
        #     decision = random_strategy()
        #     generate_report(decision)
        #     logging.info(f'Trade Decision: {decision}')
        #     time.sleep(config['trading_interval_minutes'] * 60)
        
    except Exception as e:
        logging.error(f'Error: {e}')
        raise

if __name__ == "__main__":
    main()
