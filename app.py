from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    jsonify,
    send_file,
    session
)

from flask_sqlalchemy import SQLAlchemy

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import os
import io
import ipaddress
import requests


# ============================================================
# REPORTLAB
# ============================================================

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib import colors

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)

from reportlab.lib.enums import (
    TA_CENTER
)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "sentinelrag-secret-key-change-this"
)


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


# ============================================================
# DATABASE
# ============================================================

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///"
    + os.path.join(
        BASE_DIR,
        "database",
        "sentinelrag.db"
    )
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db = SQLAlchemy(app)


# ============================================================
# LOGIN
# ============================================================

login_manager = LoginManager(app)

login_manager.login_view = "login"


# ============================================================
# USER MODEL
# ============================================================

class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(30),
        default="Analyst"
    )


# ============================================================
# USER LOADER
# ============================================================

@login_manager.user_loader
def load_user(user_id):

    try:

        return db.session.get(
            User,
            int(user_id)
        )

    except Exception:

        return None


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# SIGNUP
# ============================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )


    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()


        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        password = request.form.get(
            "password",
            ""
        )


        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        if not name or not email or not password:

            flash(
                "Please fill all fields.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("signup")
            )


        existing_user = User.query.filter_by(
            email=email
        ).first()


        if existing_user:

            flash(
                "Account already exists.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        user = User(

            name=name,

            email=email,

            password=generate_password_hash(
                password
            ),

            role="Analyst"
        )


        db.session.add(user)

        db.session.commit()


        flash(
            "Account created successfully.",
            "success"
        )


        return redirect(
            url_for("login")
        )


    return render_template(
        "signup.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )


    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        password = request.form.get(
            "password",
            ""
        )


        user = User.query.filter_by(
            email=email
        ).first()


        if user and check_password_hash(
            user.password,
            password
        ):

            login_user(user)

            return redirect(
                url_for("dashboard")
            )


        flash(
            "Invalid email or password.",
            "error"
        )


    return render_template(
        "login.html"
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html"
    )


# ============================================================
# IP DETECTION
# ============================================================

def detect_ip(value):

    """
    Automatically detects:

    IPv4
    IPv6
    PUBLIC
    PRIVATE
    LOOPBACK
    LINK-LOCAL
    MULTICAST
    UNSPECIFIED
    """

    value = str(value or "").strip()


    try:

        ip = ipaddress.ip_address(
            value
        )

    except ValueError:

        return None


    # --------------------------------------------------------
    # VERSION
    # --------------------------------------------------------

    version = (
        "IPv4"
        if ip.version == 4
        else "IPv6"
    )


    # --------------------------------------------------------
    # TYPE
    # --------------------------------------------------------

    if ip.is_loopback:

        ip_type = "LOOPBACK"

        purpose = (
            "Localhost / Loopback Address"
        )


    elif ip.is_private:

        ip_type = "PRIVATE"

        purpose = (
            "Private Internal Network Address"
        )


    elif ip.is_link_local:

        ip_type = "LINK-LOCAL"

        purpose = (
            "Link-local Network Address"
        )


    elif ip.is_multicast:

        ip_type = "MULTICAST"

        purpose = (
            "Multicast Address"
        )


    elif ip.is_unspecified:

        ip_type = "UNSPECIFIED"

        purpose = (
            "Unspecified Address"
        )


    else:

        ip_type = "PUBLIC"

        purpose = (
            "Internet-routable Public Address"
        )


    return {

        "ip": str(ip),

        "version": version,

        "type": ip_type,

        "purpose": purpose
    }


# ============================================================
# PUBLIC IP INTELLIGENCE
# ============================================================

def get_public_ip_intelligence(ip):

    """
    Collects real available information.

    Sources:

    1. ipwho.is
       - country
       - region
       - city
       - latitude
       - longitude
       - ISP
       - organization
       - ASN
       - domain
       - timezone

    2. AbuseIPDB
       - total reports
       - abuse confidence
       - usage type
       - ISP
       - domain
       - last reported
       - country

    AbuseIPDB requires:

        ABUSEIPDB_API_KEY

    environment variable.
    """


    result = {

        "country": "Unknown",

        "country_code": "Unknown",

        "region": "Unknown",

        "city": "Unknown",

        "latitude": None,

        "longitude": None,

        "timezone": "Unknown",

        "isp": "Unknown",

        "organization": "Unknown",

        "asn": "Unknown",

        "domain": "Unknown",

        "hostname": "Unknown",

        "usage_type": "Unknown",

        "total_reports": 0,

        "abuse_confidence": 0,

        "last_reported_at": "Never",

        "source": "Public IP Intelligence",

        "description": (
            "Public IP detected. "
            "Available external intelligence "
            "was collected."
        ),

        "mitre": []
    }


    # ========================================================
    # IPWHO.IS
    # ========================================================

    try:

        response = requests.get(

            f"https://ipwho.is/{ip}",

            timeout=8
        )


        if response.ok:

            data = response.json()


            if data.get("success"):

                result["country"] = (
                    data.get("country")
                    or "Unknown"
                )


                result["country_code"] = (
                    data.get("country_code")
                    or "Unknown"
                )


                result["region"] = (
                    data.get("region")
                    or "Unknown"
                )


                result["city"] = (
                    data.get("city")
                    or "Unknown"
                )


                result["latitude"] = (
                    data.get("latitude")
                )


                result["longitude"] = (
                    data.get("longitude")
                )


                timezone_data = data.get(
                    "timezone",
                    {}
                )


                if isinstance(
                    timezone_data,
                    dict
                ):

                    result["timezone"] = (
                        timezone_data.get(
                            "id"
                        )
                        or "Unknown"
                    )


                connection = data.get(
                    "connection",
                    {}
                )


                if isinstance(
                    connection,
                    dict
                ):

                    result["isp"] = (

                        connection.get(
                            "isp"
                        )

                        or "Unknown"
                    )


                    result["organization"] = (

                        connection.get(
                            "org"
                        )

                        or "Unknown"
                    )


                    result["asn"] = (

                        connection.get(
                            "asn"
                        )

                        or "Unknown"
                    )


                    result["domain"] = (

                        connection.get(
                            "domain"
                        )

                        or "Unknown"
                    )


                result["hostname"] = (

                    data.get(
                        "hostname"
                    )

                    or "Unknown"
                )


    except Exception as e:

        print(
            "IPWHO ERROR:",
            str(e)
        )


    # ========================================================
    # ABUSEIPDB
    # ========================================================

    api_key = os.environ.get(
        "ABUSEIPDB_API_KEY",
        ""
    ).strip()


    if api_key:

        try:

            response = requests.get(

                "https://api.abuseipdb.com/api/v2/check",

                headers={

                    "Key": api_key,

                    "Accept":
                        "application/json"
                },

                params={

                    "ipAddress": ip,

                    "maxAgeInDays": 90
                },

                timeout=10
            )


            if response.ok:

                abuse_data = (
                    response
                    .json()
                    .get(
                        "data",
                        {}
                    )
                )


                # --------------------------------------------
                # COUNTRY
                # --------------------------------------------

                result["country_code"] = (

                    abuse_data.get(
                        "countryCode"
                    )

                    or result["country_code"]
                )


                # --------------------------------------------
                # ISP
                # --------------------------------------------

                result["isp"] = (

                    abuse_data.get(
                        "isp"
                    )

                    or result["isp"]
                )


                # --------------------------------------------
                # DOMAIN
                # --------------------------------------------

                result["domain"] = (

                    abuse_data.get(
                        "domain"
                    )

                    or result["domain"]
                )


                # --------------------------------------------
                # USAGE TYPE
                # --------------------------------------------

                result["usage_type"] = (

                    abuse_data.get(
                        "usageType"
                    )

                    or "Unknown"
                )


                # --------------------------------------------
                # REPORTS
                # --------------------------------------------

                result["total_reports"] = int(

                    abuse_data.get(
                        "totalReports",
                        0
                    )

                    or 0
                )


                # --------------------------------------------
                # CONFIDENCE
                # --------------------------------------------

                result["abuse_confidence"] = float(

                    abuse_data.get(
                        "abuseConfidenceScore",
                        0
                    )

                    or 0
                )


                # --------------------------------------------
                # LAST REPORTED
                # --------------------------------------------

                result["last_reported_at"] = (

                    abuse_data.get(
                        "lastReportedAt"
                    )

                    or "Never"
                )


                # --------------------------------------------
                # SOURCE
                # --------------------------------------------

                result["source"] = (
                    "AbuseIPDB + ipwho.is"
                )


                # --------------------------------------------
                # DESCRIPTION
                # --------------------------------------------

                if result["total_reports"] > 0:

                    result["description"] = (

                        "AbuseIPDB reports "

                        f"{result['total_reports']} "

                        "report(s) for this IP address."
                    )

                else:

                    result["description"] = (

                        "No AbuseIPDB reports were "
                        "returned for this IP within "
                        "the configured look-back period."
                    )


        except Exception as e:

            print(
                "ABUSEIPDB ERROR:",
                str(e)
            )


    else:

        result["description"] = (

            "Public IP metadata was collected. "
            "AbuseIPDB threat-report data is unavailable "
            "because ABUSEIPDB_API_KEY is not configured."
        )


    return result


# ============================================================
# PRIVATE / LOCAL IP ANALYSIS
# ============================================================

def analyze_local_ip(ip_info):

    """
    Does NOT invent Internet threat reports.

    Private and loopback IPs do not have a public
    Internet owner/location in the same way as
    public IP addresses.

    We therefore report their real network meaning.
    """


    ip = ip_info["ip"]

    version = ip_info["version"]

    ip_type = ip_info["type"]


    # ========================================================
    # LOOPBACK
    # ========================================================

    if ip_type == "LOOPBACK":

        severity = "LOW"

        confidence = 100

        classification = (
            "LOOPBACK / LOW RISK"
        )

        description = (

            f"{ip} is a {version} loopback address. "

            "It is used by a computer to communicate "
            "with itself and is not normally an "
            "Internet-routable destination."
        )

        source = (
            "Python ipaddress / Local Classification"
        )

        purpose = (
            "Localhost / Loopback"
        )


    # ========================================================
    # PRIVATE
    # ========================================================

    elif ip_type == "PRIVATE":

        severity = "LOW"

        confidence = 100

        classification = (
            "PRIVATE NETWORK / LOW RISK"
        )

        description = (

            f"{ip} is a {version} private address. "

            "It is intended for internal/local network "
            "communication and is not directly "
            "Internet-routable."
        )

        source = (
            "Python ipaddress / Local Classification"
        )

        purpose = (
            "Private Internal Network"
        )


    # ========================================================
    # LINK LOCAL
    # ========================================================

    elif ip_type == "LINK-LOCAL":

        severity = "LOW"

        confidence = 100

        classification = (
            "LINK-LOCAL / LOW RISK"
        )

        description = (

            f"{ip} is a {version} link-local address. "

            "It is intended for communication on the "
            "local network segment."
        )

        source = (
            "Python ipaddress / Local Classification"
        )

        purpose = (
            "Link-local Network"
        )


    # ========================================================
    # MULTICAST
    # ========================================================

    elif ip_type == "MULTICAST":

        severity = "LOW"

        confidence = 100

        classification = (
            "MULTICAST / LOW RISK"
        )

        description = (

            f"{ip} is a {version} multicast address."
        )

        source = (
            "Python ipaddress / Local Classification"
        )

        purpose = (
            "Multicast Address"
        )


    # ========================================================
    # UNSPECIFIED
    # ========================================================

    elif ip_type == "UNSPECIFIED":

        severity = "LOW"

        confidence = 100

        classification = (
            "UNSPECIFIED / LOW RISK"
        )

        description = (

            f"{ip} is an unspecified {version} address."
        )

        source = (
            "Python ipaddress / Local Classification"
        )

        purpose = (
            "Unspecified Address"
        )


    else:

        severity = "UNKNOWN"

        confidence = 90

        classification = (
            "UNKNOWN"
        )

        description = (

            f"{ip} is a {version} non-public "
            "network address."
        )

        source = (
            "Local IP Classification"
        )

        purpose = ip_info["purpose"]


    return {

        "country": "N/A",

        "country_code": "N/A",

        "region": "N/A",

        "city": "N/A",

        "latitude": None,

        "longitude": None,

        "timezone": "N/A",

        "isp": "N/A",

        "organization": "N/A",

        "asn": "N/A",

        "domain": "N/A",

        "hostname": "N/A",

        "usage_type": purpose,

        "total_reports": 0,

        "abuse_confidence": 0,

        "last_reported_at": "N/A",

        "source": source,

        "description": description,

        "mitre": [],

        "severity": severity,

        "confidence": confidence,

        "classification": classification
    }


# ============================================================
# SEVERITY SCORE
# ============================================================

def get_severity_score(severity):

    severity_scores = {

        "HIGH": 90,

        "MEDIUM": 60,

        "LOW": 20,

        "UNKNOWN": 0
    }


    return severity_scores.get(

        str(
            severity or "UNKNOWN"
        ).upper(),

        0
    )


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(
    severity,
    confidence
):

    severity_score = get_severity_score(
        severity
    )


    confidence = float(
        confidence or 0
    )


    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    risk_score = (

        severity_score * 0.60

        +

        confidence * 0.40
    )


    risk_score = max(

        0,

        min(
            100,
            risk_score
        )
    )


    # --------------------------------------------------------
    # CLASSIFICATION
    # --------------------------------------------------------

    if risk_score >= 75:

        classification = (
            "HIGH RISK"
        )


    elif risk_score >= 30:

        classification = (
            "MEDIUM RISK"
        )


    else:

        classification = (
            "LOW RISK"
        )


    return (

        round(risk_score),

        classification
    )


# ============================================================
# PUBLIC SEVERITY
# ============================================================

def calculate_public_severity(
    reports,
    abuse_confidence
):

    reports = int(
        reports or 0
    )


    abuse_confidence = float(
        abuse_confidence or 0
    )


    if (

        abuse_confidence >= 75

        or

        reports >= 100
    ):

        return "HIGH"


    if (

        abuse_confidence >= 30

        or

        reports >= 10
    ):

        return "MEDIUM"


    if (

        reports > 0

        or

        abuse_confidence > 0
    ):

        return "LOW"


    return "UNKNOWN"


# ============================================================
# PUBLIC CONFIDENCE
# ============================================================

def calculate_public_confidence(
    intelligence
):

    abuse_confidence = float(

        intelligence.get(
            "abuse_confidence",
            0
        )

        or 0
    )


    if abuse_confidence > 0:

        return max(

            0,

            min(
                100,
                abuse_confidence
            )
        )


    score = 20


    if intelligence.get(
        "country"
    ) not in [
        None,
        "",
        "Unknown"
    ]:

        score += 20


    if intelligence.get(
        "isp"
    ) not in [
        None,
        "",
        "Unknown"
    ]:

        score += 20


    if intelligence.get(
        "organization"
    ) not in [
        None,
        "",
        "Unknown"
    ]:

        score += 10


    if intelligence.get(
        "asn"
    ) not in [
        None,
        "",
        "Unknown"
    ]:

        score += 10


    if intelligence.get(
        "description"
    ):

        score += 10


    return max(

        0,

        min(
            100,
            score
        )
    )


# ============================================================
# ANALYZE IP API
# ============================================================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
@login_required
def analyze_ioc():

    try:

        data = request.get_json(
            silent=True
        ) or {}


        value = str(

            data.get(
                "value",
                ""
            )
        ).strip()


        # ====================================================
        # VALIDATION
        # ====================================================

        if not value:

            return jsonify({

                "error":
                    "IP address is required."
            }), 400


        # ====================================================
        # AUTO DETECT
        # ====================================================

        ip_info = detect_ip(
            value
        )


        if not ip_info:

            return jsonify({

                "error":
                    "Invalid IP address. "
                    "Enter a valid IPv4 or IPv6 address."
            }), 400


        # ====================================================
        # LOCAL / PRIVATE
        # ====================================================

        if ip_info["type"] != "PUBLIC":

            intelligence = analyze_local_ip(
                ip_info
            )


        # ====================================================
        # PUBLIC
        # ====================================================

        else:

            intelligence = (
                get_public_ip_intelligence(
                    ip_info["ip"]
                )
            )


            reports = int(

                intelligence.get(
                    "total_reports",
                    0
                )

                or 0
            )


            abuse_confidence = float(

                intelligence.get(
                    "abuse_confidence",
                    0
                )

                or 0
            )


            severity = calculate_public_severity(

                reports,

                abuse_confidence
            )


            confidence = calculate_public_confidence(

                intelligence
            )


            intelligence["severity"] = severity

            intelligence["confidence"] = confidence


        # ====================================================
        # COMMON VALUES
        # ====================================================

        severity = str(

            intelligence.get(
                "severity",
                "UNKNOWN"
            )
        ).upper()


        confidence = float(

            intelligence.get(
                "confidence",
                0
            )

            or 0
        )


        total_reports = int(

            intelligence.get(
                "total_reports",
                0
            )

            or 0
        )


        # ====================================================
        # RISK
        # ====================================================

        risk_score, calculated_classification = (
            calculate_risk(

                severity,

                confidence
            )
        )


        # ====================================================
        # LOCAL CLASSIFICATION OVERRIDE
        # ====================================================

        if ip_info["type"] != "PUBLIC":

            classification = intelligence.get(

                "classification",

                calculated_classification
            )

        else:

            classification = (
                calculated_classification
            )


        # ====================================================
        # EVIDENCE
        # ====================================================

        evidence = 0


        if intelligence.get(
            "description"
        ):

            evidence += 1


        mitre = intelligence.get(
            "mitre",
            []
        )


        if isinstance(
            mitre,
            list
        ):

            evidence += len(
                mitre
            )


        if total_reports > 0:

            evidence += 1


        if evidence == 0:

            evidence = 1


        # ====================================================
        # FINAL RESULT
        # ====================================================

        result = {

            "indicator":
                ip_info["ip"],


            "type":
                "IP",


            "ip_version":
                ip_info["version"],


            "ip_type":
                ip_info["type"],


            "purpose":
                ip_info["purpose"],


            "classification":
                classification,


            "risk_score":
                risk_score,


            "confidence":
                round(
                    confidence
                ),


            "evidence":
                evidence,


            "severity":
                severity,


            "description":
                intelligence.get(

                    "description",

                    "No description available."
                ),


            "mitre":
                mitre,


            "status":
                "Collected",


            "source":
                intelligence.get(

                    "source",

                    "SentinelRAG"
                ),


            # ------------------------------------------------
            # LOCATION
            # ------------------------------------------------

            "country":
                intelligence.get(

                    "country",

                    "Unknown"
                ),


            "country_code":
                intelligence.get(

                    "country_code",

                    "Unknown"
                ),


            "region":
                intelligence.get(

                    "region",

                    "Unknown"
                ),


            "city":
                intelligence.get(

                    "city",

                    "Unknown"
                ),


            "latitude":
                intelligence.get(
                    "latitude"
                ),


            "longitude":
                intelligence.get(
                    "longitude"
                ),


            "timezone":
                intelligence.get(

                    "timezone",

                    "Unknown"
                ),


            # ------------------------------------------------
            # NETWORK
            # ------------------------------------------------

            "isp":
                intelligence.get(

                    "isp",

                    "Unknown"
                ),


            "organization":
                intelligence.get(

                    "organization",

                    "Unknown"
                ),


            "asn":
                intelligence.get(

                    "asn",

                    "Unknown"
                ),


            "usage_type":
                intelligence.get(

                    "usage_type",

                    "Unknown"
                ),


            "domain":
                intelligence.get(

                    "domain",

                    "Unknown"
                ),


            "hostname":
                intelligence.get(

                    "hostname",

                    "Unknown"
                ),


            # ------------------------------------------------
            # THREAT INTELLIGENCE
            # ------------------------------------------------

            "total_reports":
                total_reports,


            "abuse_confidence":
                intelligence.get(

                    "abuse_confidence",

                    0
                ),


            "last_reported_at":
                intelligence.get(

                    "last_reported_at",

                    "Never"
                )
        }


        # ====================================================
        # SAVE FOR REPORT
        # ====================================================

        session[
            "last_analysis"
        ] = result


        session.modified = True


        # ====================================================
        # TERMINAL OUTPUT
        # ====================================================

        print(
            "\n=========================================="
        )

        print(
            "SENTINELRAG ANALYSIS"
        )

        print(
            "IP:",
            result["indicator"]
        )

        print(
            "VERSION:",
            result["ip_version"]
        )

        print(
            "TYPE:",
            result["ip_type"]
        )

        print(
            "COUNTRY:",
            result["country"]
        )

        print(
            "REGION:",
            result["region"]
        )

        print(
            "CITY:",
            result["city"]
        )

        print(
            "ISP:",
            result["isp"]
        )

        print(
            "ORGANIZATION:",
            result["organization"]
        )

        print(
            "ASN:",
            result["asn"]
        )

        print(
            "REPORTS:",
            result["total_reports"]
        )

        print(
            "ABUSE CONFIDENCE:",
            result["abuse_confidence"]
        )

        print(
            "SEVERITY:",
            result["severity"]
        )

        print(
            "CONFIDENCE:",
            result["confidence"]
        )

        print(
            "RISK:",
            result["risk_score"]
        )

        print(
            "CLASSIFICATION:",
            result["classification"]
        )

        print(
            "==========================================\n"
        )


        return jsonify(
            result
        )


    except Exception as e:

        print(
            "ANALYSIS ERROR:",
            str(e)
        )


        return jsonify({

            "error":
                "Analysis failed: "
                + str(e)

        }), 500


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/report/download",
    methods=["GET", "POST"]
)
@login_required
def download_report():

    # --------------------------------------------------------
    # GET/POST BOTH SUPPORTED
    # --------------------------------------------------------

    result = session.get(
        "last_analysis"
    )


    # --------------------------------------------------------
    # OPTIONAL POST DATA
    # --------------------------------------------------------

    if request.method == "POST":

        try:

            body = request.get_json(
                silent=True
            ) or {}


            posted_analysis = body.get(
                "analysis"
            )


            if isinstance(
                posted_analysis,
                dict
            ):

                result = posted_analysis


                session[
                    "last_analysis"
                ] = result


                session.modified = True


        except Exception as e:

            print(
                "REPORT POST DATA ERROR:",
                str(e)
            )


    # --------------------------------------------------------
    # CHECK RESULT
    # --------------------------------------------------------

    if not result:

        return jsonify({

            "error":
                "No analysis available. "
                "Analyze an IP first."

        }), 400


    # ========================================================
    # PDF BUFFER
    # ========================================================

    buffer = io.BytesIO()


    document = SimpleDocTemplate(

        buffer,

        pagesize=A4,

        rightMargin=40,

        leftMargin=40,

        topMargin=40,

        bottomMargin=40
    )


    styles = getSampleStyleSheet()


    title_style = styles["Title"]


    title_style.alignment = (
        TA_CENTER
    )


    heading_style = styles[
        "Heading2"
    ]


    normal_style = styles[
        "BodyText"
    ]


    small_style = ParagraphStyle(

        "Small",

        parent=normal_style,

        fontSize=9,

        leading=12
    )


    story = []


    # ========================================================
    # TITLE
    # ========================================================

    story.append(

        Paragraph(

            "SENTINELRAG",

            title_style
        )
    )


    story.append(

        Paragraph(

            "Threat Intelligence Report",

            heading_style
        )
    )


    story.append(

        Spacer(
            1,
            18
        )
    )


    # ========================================================
    # MAIN DETAILS
    # ========================================================

    table_data = [

        [
            "IP Address",
            result.get(
                "indicator",
                "N/A"
            )
        ],


        [
            "IP Version",
            result.get(
                "ip_version",
                "N/A"
            )
        ],


        [
            "Network Type",
            result.get(
                "ip_type",
                "N/A"
            )
        ],


        [
            "Purpose",
            result.get(
                "purpose",
                "N/A"
            )
        ],


        [
            "Country",
            result.get(
                "country",
                "N/A"
            )
        ],


        [
            "Country Code",
            result.get(
                "country_code",
                "N/A"
            )
        ],


        [
            "Region",
            result.get(
                "region",
                "N/A"
            )
        ],


        [
            "City",
            result.get(
                "city",
                "N/A"
            )
        ],


        [
            "Latitude",
            str(
                result.get(
                    "latitude",
                    "N/A"
                )
            )
        ],


        [
            "Longitude",
            str(
                result.get(
                    "longitude",
                    "N/A"
                )
            )
        ],


        [
            "ISP",
            result.get(
                "isp",
                "N/A"
            )
        ],


        [
            "Organization",
            result.get(
                "organization",
                "N/A"
            )
        ],


        [
            "ASN",
            result.get(
                "asn",
                "N/A"
            )
        ],


        [
            "Usage Type",
            result.get(
                "usage_type",
                "N/A"
            )
        ],


        [
            "Domain",
            result.get(
                "domain",
                "N/A"
            )
        ],


        [
            "Hostname",
            result.get(
                "hostname",
                "N/A"
            )
        ],


        [
            "Total Reports",
            str(
                result.get(
                    "total_reports",
                    0
                )
            )
        ],


        [
            "Abuse Confidence",
            f"{result.get('abuse_confidence', 0)}%"
        ],


        [
            "Severity",
            result.get(
                "severity",
                "UNKNOWN"
            )
        ],


        [
            "Confidence",
            f"{result.get('confidence', 0)}%"
        ],


        [
            "Risk Score",
            f"{result.get('risk_score', 0)} / 100"
        ],


        [
            "Classification",
            result.get(
                "classification",
                "UNKNOWN"
            )
        ],


        [
            "Source",
            result.get(
                "source",
                "SentinelRAG"
            )
        ],


        [
            "Last Reported",
            result.get(
                "last_reported_at",
                "N/A"
            )
        ]
    ]


    # ========================================================
    # TABLE
    # ========================================================

    table = Table(

        table_data,

        colWidths=[
            155,
            325
        ]
    )


    table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor(
                    "#eeeeee"
                )
            ),


            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),


            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica"
            ),


            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),


            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),


            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),


            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),


            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])
    )


    story.append(
        table
    )


    story.append(
        Spacer(
            1,
            20
        )
    )


    # ========================================================
    # DESCRIPTION
    # ========================================================

    story.append(

        Paragraph(

            "Threat Description",

            heading_style
        )
    )


    description = str(

        result.get(

            "description",

            "No description available."
        )
    )


    story.append(

        Paragraph(

            description,

            normal_style
        )
    )


    story.append(
        Spacer(
            1,
            18
        )
    )


    # ========================================================
    # MITRE
    # ========================================================

    story.append(

        Paragraph(

            "MITRE ATT&CK",

            heading_style
        )
    )


    mitre = result.get(
        "mitre",
        []
    )


    if isinstance(
        mitre,
        list
    ) and mitre:

        for technique in mitre:

            story.append(

                Paragraph(

                    str(
                        technique
                    ),

                    normal_style
                )
            )


    else:

        story.append(

            Paragraph(

                "No MITRE ATT&CK techniques identified.",

                normal_style
            )
        )


    story.append(
        Spacer(
            1,
            20
        )
    )


    # ========================================================
    # ANALYSIS NOTE
    # ========================================================

    if result.get(
        "ip_type"
    ) != "PUBLIC":

        note = (

            "Note: This address is not a normal "
            "Internet-routable public IP. Country, "
            "ISP and Internet abuse-report fields may "
            "therefore be unavailable. The report "
            "contains the actual network classification "
            "of the address rather than fabricated "
            "Internet threat data."
        )

    else:

        note = (

            "Threat intelligence and geolocation values "
            "are based on the external sources available "
            "to SentinelRAG at analysis time."
        )


    story.append(

        Paragraph(

            note,

            small_style
        )
    )


    story.append(
        Spacer(
            1,
            20
        )
    )


    story.append(

        Paragraph(

            "Generated by SentinelRAG Threat Intelligence System",

            small_style
        )
    )


    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story
    )


    buffer.seek(0)


    # ========================================================
    # FILE NAME
    # ========================================================

    safe_ip = str(

        result.get(
            "indicator",
            "IP"
        )

    ).replace(
        ":",
        "_"
    ).replace(
        "/",
        "_"
    )


    filename = (

        "SentinelRAG_Threat_Report_"

        + safe_ip

        + ".pdf"
    )


    # ========================================================
    # SEND PDF
    # ========================================================

    return send_file(

        buffer,

        as_attachment=True,

        download_name=filename,

        mimetype="application/pdf"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()


    flash(
        "Logged out successfully.",
        "success"
    )


    return redirect(
        url_for("index")
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

with app.app_context():

    os.makedirs(

        os.path.join(
            BASE_DIR,
            "database"
        ),

        exist_ok=True
    )


    db.create_all()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(

        debug=True,

        host="0.0.0.0",

        port=int(

            os.environ.get(
                "PORT",
                5001
            )
        )
    )