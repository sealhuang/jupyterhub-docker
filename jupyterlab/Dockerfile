FROM jupyter/scipy-notebook:137a295ff71b

LABEL maintainer="Lijie Huang <huanglijie@outlook.com>"

USER root
COPY ./sources.list /etc/apt/
COPY ./fonts /usr/share/fonts/
RUN fc-cache -fv

# APT packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    fonts-dejavu \
    gfortran \
    gcc \
    xvfb \
    libxtst6 \
    libgconf-2-4 \
    libgmp-dev \
    libxml2-dev \
    libxslt-dev \
    vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

USER $NB_UID

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple retrying==1.3.3

# Conda packages
# Sage conflicts with the latest jupyterhub, thus we must relax the pinning
RUN conda config --set show_channel_urls yes && \
    conda config --prepend channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/plotly && \
    conda config --prepend  channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/free/ && \
    conda config --prepend channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main/ && \
#    conda config --prepend channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/cloud/conda-forge && \
    conda update conda pandas

RUN conda install --yes \
    'plotly' \
    'plotly-orca=1.2' \
    'psutil' \
    'requests' \
    'clickhouse-driver' \
    'tzlocal' \
    'ipython' \
    'jupyter_contrib_nbextensions' && \
    conda clean -tipsy && \
    fix-permissions $CONDA_DIR

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple jieba wordcloud nbdime weasyprint pymongo kafka-python oss2

# Install svgutils
USER root
RUN cd /tmp && \
    git clone https://github.com/sealhuang/svg_utils.git && \
    cd svg_utils && \
    python setup.py install && \
    cd && \
    rm -rf /tmp/svg_utils

RUN cd /tmp && \
    git clone https://github.com/sealhuang/SmartyDoc.git && \
    cd SmartyDoc && \
    python setup.py install && \
    cp -r nbextensions/printview2 /opt/conda/share/jupyter/nbextensions && \
    cd && \
    rm -rf /tmp/SmartyDoc && \
    fix-permissions $CONDA_DIR && \
    fix-permissions /home/$NB_USER

# XXX: fix chrome-sandbox security issus
#RUN chown root:users /opt/conda/lib/orca_app/chrome-sandbox && \
#    chmod 4755 /opt/conda/lib/orca_app/chrome-sandbox

USER $NB_UID

RUN jupyter nbextension enable codefolding/main && \
    jupyter nbextension enable toc2/main && \
    jupyter nbextension enable hide_input_all/main && \
    jupyter nbextension enable printview2/main

# Add conda env hook
COPY ./conda-activate.sh /usr/local/bin/before-notebook.d/

