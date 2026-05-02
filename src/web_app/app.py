# Mind the App: Detecting Dual-Use Applications
# Copyright (C) 2026 Amir Hassanali
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# app.py  -- flask web app for my dissertation
import os
import uuid
import sys
import joblib
import traceback
import pandas as pd

from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

from apk_analysis.APK_analyser import APK, APKanalyser
from utils.config import (
    S_KEY,
    MODELS_FOLDER,
    UPLOAD_FOLDER,
    JSON_PATH,
    M_PACKAGE_LOCATION,
)

app = Flask(__name__)
app.secret_key = S_KEY

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# 2 GB max --- prevent malicious uploads that are file bombs
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024


# make folders if they dont exist yet
if not os.path.exists(UPLOAD_FOLDER):  # pyright: ignore
    os.makedirs(UPLOAD_FOLDER)  # pyright: ignore

if not os.path.exists(MODELS_FOLDER):  # pyright: ignore
    print("No folder with trained models, please train models first.")
    exit()


def allowed_file(fname):
    """only accept apk files"""
    dot_in_name = "." in fname
    if not dot_in_name:
        return False

    parts = fname.rsplit(".", 1)
    ext = parts[1].lower()

    if ext == "apk":
        return True
    return False


def get_available_models():
    """scan models folder and return list of pkl files the user can choose from"""
    result = []

    all_files = os.listdir(MODELS_FOLDER)

    for f in all_files:
        if f.endswith(".pkl"):
            if "hard" in f:
                result.append(f"{f} (DISCRETE - no risk score)")
            else:
                result.append(f)

    # sort alphabetically so drop down looks better
    result.sort()
    return result


def load_model_from_disk(model_name):
    """Load a pkl model, using joblib because thats what train_model.py saves with"""
    # For hard consensus model remove the part in parenthesis
    if "DISCRETE" in model_name:
        model_name = model_name.split(" ")[0]

    full_path = os.path.join(MODELS_FOLDER, model_name)  # pyright: ignore

    if not os.path.exists(full_path):
        raise FileNotFoundError("Could not find model file: " + full_path)

    models_src = M_PACKAGE_LOCATION  # pyright: ignore
    if models_src not in sys.path:
        sys.path.insert(0, models_src)  # pyright: ignore

    loaded = joblib.load(full_path)
    return loaded


def get_sus_perms_list():
    """loads the suspicious permissions list from JSON file, returns an empty list if the JSON is not found. Means that the perm column will be empty"""
    perms = []

    json_exists = os.path.exists(JSON_PATH)  # pyright: ignore

    if not json_exists:
        print(
            "WARNING: suspicious_permissions.json not found, perm features will be empty"
        )
        return perms

    perms = APKanalyser.get_suspicious_permissions(Path(JSON_PATH))  # pyright: ignore
    return perms


def do_static_analysis(apk_path_str, sus_perms):
    """Runs the Static analysis module (runs on initialisation of the APK object) on the APK and gets the metadata"""
    apk_obj = APK(apk_path_str, sus_perms, head_only=False)
    meta = apk_obj.get_metadata()
    return meta


def build_feature_dict(meta, sus_perms):
    """converts raw metadata into the feature dict that matches training CSV columns. See export_features() in APK_analyser.py for the exact column names"""

    features = {}

    val = meta.get("targets_old_sdk")
    if val:
        features["targets_old_sdk"] = 1
    else:
        features["targets_old_sdk"] = 0

    val = meta.get(
        "boot_persistance"
    )  # note: typo in original analyser, persistance not persistence
    if val:
        features["boot_persistence"] = 1
    else:
        features["boot_persistence"] = 0

    val = meta.get("user_persistance")
    if val:
        features["user_persistence"] = 1
    else:
        features["user_persistence"] = 0

    val = meta.get("suspicious_libraries")
    if val:
        features["suspicious_libraries"] = 1
    else:
        features["suspicious_libraries"] = 0

    features["num_suspicious_ips"] = meta.get("num_sus_ips", 0)
    features["num_suspicious_domains"] = meta.get("num_sus_domains", 0)

    perm_list = meta.get("permissions", [])
    features["num_total_permissions"] = len(perm_list)

    sus_perm_list = meta.get("suspicious_permissions", [])
    features["num_suspicious_permissions"] = len(sus_perm_list)

    val = meta.get("exported_provider")
    if val:
        features["exported_provider"] = 1
    else:
        features["exported_provider"] = 0

    val = meta.get("suspicious_service")
    if val:
        features["suspicious_service"] = 1
    else:
        features["suspicious_service"] = 0

    features["suspicious_receiver_score"] = meta.get("suspicious_receiver_score", 0)

    val = meta.get("hidden_icon")
    if val:
        features["hidden_icon"] = 1
    else:
        features["hidden_icon"] = 0

    all_app_perms = set()

    explicit_perms = meta.get("permissions", [])
    implied_perms = meta.get("suspicious_implied_permissions", [])

    for p in explicit_perms:
        all_app_perms.add(p)

    for p in implied_perms:
        all_app_perms.add(p)

    # one column per suspicious permission. 1 if apk has it, 0 if not
    for perm_full_name in sus_perms:
        last_part = perm_full_name.split(".")[-1]
        col_name = "perm_" + last_part

        if perm_full_name in all_app_perms:
            features[col_name] = 1
        else:
            features[col_name] = 0

    return features


def predict_with_model(mdl, feat_dict):
    """
    Runs prediction and returns (class_label, risk_probability) where:
    - class 1 = malware/high risk, class 0 = benign
    """

    # stick the single sample into a dataframe
    rows = []
    rows.append(feat_dict)
    df = pd.DataFrame(rows)

    # fill Nones
    df = df.fillna(0)

    # try to get the feature names the model was trained with
    expected_cols = None

    if hasattr(mdl, "feature_names_in_"):
        expected_cols = mdl.feature_names_in_
    elif hasattr(mdl, "model") and hasattr(mdl.model, "feature_names_in_"):
        expected_cols = mdl.model.feature_names_in_
    elif (
        hasattr(mdl, "models")
        and len(mdl.models) > 0
        and hasattr(mdl.models[0].model, "feature_names_in_")
    ):
        # Handles consensus model by looking at first sub model
        expected_cols = mdl.models[0].model.feature_names_in_

    # Align dataframe columns to match training dataset, putting 0 for any missing columns
    if expected_cols is not None:
        for c in expected_cols:
            if c not in df.columns:
                df[c] = 0
        df = df[list(expected_cols)]

    # get the predicted class
    raw_pred = mdl.predict(df)
    pred_class = int(raw_pred[0])

    # try to get probability
    risk_prob = None

    try:
        if hasattr(mdl, "predict_probs"):
            # Handle model probabilities
            proba_arr = mdl.predict_probs(df)
            risk_prob = float(proba_arr[0][1])  # Column 1 is dual-use/malware
        else:
            proba_arr = mdl.predict_proba(df)
            # column 1 is probability of being malware
            risk_prob = float(proba_arr[0][1])
    except Exception:
        # if no proba just use the class as the score (0.0 or 1.0)
        risk_prob = float(pred_class)

    return pred_class, risk_prob


def score_to_label(score_float):
    """simple thresholds,can tweak these"""
    lbl = "LOW RISK"

    if score_float >= 0.75:
        lbl = "HIGH RISK"
    elif score_float >= 0.45:
        lbl = "MEDIUM RISK"

    return lbl


# routes
@app.route("/", methods=["GET"])
def index():
    # homepage -- shows the upload form
    mdls = get_available_models()
    return render_template("index.html", models=mdls)


@app.route("/analyse", methods=["POST"])
def analyse():
    # handles form submission from the homepage

    # basic validation
    if "apk_file" not in request.files:
        flash("No file part in the request")
        return redirect(url_for("index"))

    uploaded_file = request.files["apk_file"]

    if uploaded_file.filename == "":
        flash("You didn't select a file")
        return redirect(url_for("index"))

    chosen_model = request.form.get("model_choice", "")
    if chosen_model == "":
        flash("Please pick a model from the dropdown")
        return redirect(url_for("index"))

    if not allowed_file(uploaded_file.filename):
        flash("Only .apk files are accepted")
        return redirect(url_for("index"))

    # save with a unique prefix so parallel uploads dont clash
    clean_name = secure_filename(uploaded_file.filename)
    # Generate a random UUID and take first 8 characters for a unique prefix
    short_uid = str(uuid.uuid4())[:8]
    tmp_name = short_uid + "_" + clean_name
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], tmp_name)

    uploaded_file.save(save_path)

    # run analysis wrapped in try/finally for cleanup
    err_msg = None
    res = None

    try:
        # 1: load suspicious permissions list
        sus_perms = get_sus_perms_list()

        # 2:  static analysis
        meta = do_static_analysis(save_path, sus_perms)

        print("META TYPE:", type(meta))
        print("META KEYS:", meta.keys() if isinstance(meta, dict) else "NOT A DICT")

        for key in ["permissions", "suspicious_implied_permissions"]:
            if key in meta:
                print(f"{key} type: {type(meta[key])}")
                if meta[key] and len(meta[key]) > 0:
                    print(f"{key} first item type: {type(meta[key][0])}")
                    print(f"{key} first item: {meta[key][0]}")

        # 3: build feature vector
        feat_dict = build_feature_dict(meta, sus_perms)

        # 4: load model and predict
        mdl = load_model_from_disk(chosen_model)
        pred_cls, risk_prob = predict_with_model(mdl, feat_dict)

        # 5: format results for the template
        risk_pct = round(risk_prob * 100, 1)
        risk_lbl = score_to_label(risk_prob)

        # Some features to display
        sus_perm_names = meta.get("suspicious_permissions", [])
        all_perm_count = len(meta.get("permissions", []))
        pkg = meta.get("package_name", "unknown")

        # build a summary of the key feature values in a table
        feature_summary = {}
        feature_summary["Package Name"] = pkg
        feature_summary["Total Permissions"] = all_perm_count
        feature_summary["Suspicious Permissions"] = len(sus_perm_names)
        feature_summary["Targets Old SDK"] = (
            "Yes" if feat_dict.get("targets_old_sdk") else "No"
        )
        feature_summary["Boot Persistence"] = (
            "Yes" if feat_dict.get("boot_persistence") else "No"
        )
        feature_summary["User Persistence"] = (
            "Yes" if feat_dict.get("user_persistence") else "No"
        )
        feature_summary["Hidden Icon"] = "Yes" if feat_dict.get("hidden_icon") else "No"
        feature_summary["Suspicious Service"] = (
            "Yes" if feat_dict.get("suspicious_service") else "No"
        )
        feature_summary["Exported Provider"] = (
            "Yes" if feat_dict.get("exported_provider") else "No"
        )
        feature_summary["Suspicious Libraries"] = (
            "Yes" if feat_dict.get("suspicious_libraries") else "No"
        )
        feature_summary["Suspicious IPs Found"] = feat_dict.get("num_suspicious_ips", 0)
        feature_summary["Suspicious Domains Found"] = feat_dict.get(
            "num_suspicious_domains", 0
        )
        feature_summary["Receiver Risk Score"] = feat_dict.get(
            "suspicious_receiver_score", 0
        )

        res = {
            "apk_name": clean_name,
            "package_name": pkg,
            "predicted_class": pred_cls,
            "risk_score_pct": risk_pct,
            "risk_label": risk_lbl,
            "model_used": chosen_model,
            "sus_permissions": sus_perm_names,
            "feature_summary": feature_summary,
        }

    except Exception as ex:
        err_msg = str(ex)
        traceback.print_exc()  # print full trace to console for debugging

    finally:
        # always delete the temp apk file
        if os.path.exists(save_path):
            os.remove(save_path)

    if err_msg is not None:
        flash("Analysis failed: " + err_msg)
        return redirect(url_for("index"))

    return render_template("result.html", result=res)


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
